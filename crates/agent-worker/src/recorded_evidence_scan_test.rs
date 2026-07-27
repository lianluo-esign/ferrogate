// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The recorded-evidence source audit (#526), and the proof that it rejects.
//!
//! # What this closes
//!
//! #526's acceptance asks for a test that fails if a NEW excerpt path bypasses
//! the shared redaction. Two structural forces already exist and neither is
//! that test:
//!
//! * a new `RecordedSurface` variant does not compile until
//!   `external_actions_recorded_evidence_test.rs` gives it an artifact arm, and
//! * a new recording site cannot call a `recorded_evidence` helper without
//!   naming a surface, because every helper takes one.
//!
//! Both start from "a helper was called". Neither can force the first call, and
//! the original defect never made one: `run_authorized_rest_action` wrote
//! `response.chars().take(512)` itself, for two years, with the suite green. So
//! the guard that answers the box has to read SOURCE, in the shape
//! `ferrogate-storage` already uses for the `search_path` pin (#239/#383/#480).
//!
//! Stated plainly rather than implied: this is DETECTION, not impossibility.
//! Making bypass impossible would mean the raw bytes could not be reached
//! except through a wrapper type — a newtype over `Vec<u8>` returned by every
//! `Command`, every `TcpStream` read and every `fs::read`. That is not a thing
//! `agent-worker` can impose: the bytes arrive from `std`, from
//! `ferrogate-runtime`'s isolation trait and from `serde_json`, none of which
//! this crate defines. What it CAN impose is that turning those bytes into a
//! string is a reviewed act, and that is what the audit table below is.
//!
//! # Why the audit is a table in a test rather than a paragraph in an issue
//!
//! Acceptance box 4 asks for the audit to be recorded "including any family
//! found clean, so the next reader does not redo it". A comment saying a site is
//! clean rots silently. A table the suite reads cannot: every raw-capture site
//! in every recording source must appear here with a verdict, so a site that
//! changes shape, moves function, or appears for the first time fails until
//! someone writes down what they concluded about it.
//!
//! # Exactly what the audit is keyed on, and what that leaves uncovered
//!
//! The first version of this table was keyed on `(file, enclosing fn)` alone,
//! which blessed whole FUNCTIONS: a second raw capture added INSIDE
//! `run_authorized_rest_action` — #526's own leak — matched the existing row,
//! left `unaudited` empty, and passed. The claim above ("changes shape") was
//! therefore false in the one direction that mattered, so the key was widened
//! rather than the claim narrowed. A row now signs off on
//! `(file, fn, idiom, EXACT number of occurrences)`, and
//! [`a_capture_added_inside_an_already_audited_function_is_not_blessed_by_its_row`]
//! runs that precise mutation against the real `external_actions.rs`.
//!
//! Three things the widened key still does not hold, named here because this is
//! where the next reader looks:
//!
//! * **Function-name aliasing.** `enclosing_function` reports the nearest `fn`
//!   above the site, not a path, so the two distinct `fn parse` bodies in
//!   `backends.rs` (the guest-agent handshake and the guest RPC start response)
//!   share ONE row and ONE verdict. The occurrence count means a third `fn parse`
//!   that ADDS a capture fails; a third one that takes over an existing
//!   occurrence 1:1 does not.
//! * **Idiom blindness to paths that never decode.** All four idioms are a
//!   decode or a `take` truncation. A recording path that receives text already
//!   decoded — a `String` out of `serde_json`, a `read_to_string`, a slice of an
//!   existing `String` — matches nothing. Concretely and not hypothetically:
//!   the host-ingestion leak #526's own previous commit fixed (the host
//!   recording guest-authored `String`s that `serde_json` had already decoded)
//!   would NOT have been found by this scan. `RecordedSurface`'s exhaustive
//!   match and `recorded_metadata` are the guards for that shape; this one is
//!   not.
//! * **Detection, not impossibility**, as the section above already says: the
//!   table makes a new decode a reviewed act, it does not make one impossible.

use std::collections::BTreeMap;

use super::recorded_evidence_scan_test_support::{
    code_only, is_recording_source, scan_raw_captures, scan_redactors, scan_surface_register,
    RawCaptureSite, RedactorSite, RAW_CAPTURE_IDIOMS,
};

/// The file that owns the redaction. Every other recording source is audited
/// against it.
const CHOKEPOINT: &str = "recorded_evidence.rs";

/// What a reviewer concluded about one raw-capture site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawCaptureVerdict {
    /// This site IS the shared chokepoint's own implementation.
    Chokepoint,
    /// The bytes are workload- or upstream-controlled AND reach a recorded
    /// artifact — but only through a `recorded_evidence` helper.
    RoutedThroughChokepoint,
    /// The bytes are not workload- or upstream-controlled. The reason names
    /// whose bytes they are and where they end up, because "not attacker
    /// controlled" is a judgement and the next reader is entitled to re-check
    /// it rather than take it.
    NotAttackerControlled,
}

/// One audited key: a `(file, enclosing fn)` pair, the idioms found there, and
/// HOW MANY of each a reviewer actually looked at.
///
/// The count is the part that makes "changes shape" true. Without it the row
/// blesses the whole function, and the mutation that created #526 — one more
/// raw decode added inside `run_authorized_rest_action` — matches the row and
/// passes.
#[derive(Debug, Clone, Copy)]
struct AuditedCaptures {
    file: &'static str,
    /// The enclosing `fn`. A line number would be invalidated by any edit above
    /// it, which would train the next reader to re-bless the table without
    /// reading it.
    function: &'static str,
    /// `(idiom, the exact number of occurrences signed off)`. More than this,
    /// or an idiom that is not listed, fails.
    captures: &'static [(&'static str, usize)],
    verdict: RawCaptureVerdict,
    reason: &'static str,
}

/// EVERY raw-capture site in every recording source of this crate, with the
/// verdict on it. This is #526's audit, in the only form that cannot rot.
///
/// 17 keys, 27 occurrences. Both totals are re-derived from the tree by
/// [`every_raw_capture_in_the_crate_has_an_audit_verdict`] in both directions,
/// so neither number is trusted from this comment.
const RAW_CAPTURE_AUDIT: [AuditedCaptures; 17] = [
    AuditedCaptures {
        file: CHOKEPOINT,
        function: "recorded_excerpt",
        captures: &[("from_utf8_lossy(", 1)],
        verdict: RawCaptureVerdict::Chokepoint,
        reason: "the decode every non-REST family used to do for itself",
    },
    AuditedCaptures {
        file: CHOKEPOINT,
        function: "recorded_http_excerpt",
        captures: &[(".chars().take(", 1)],
        verdict: RawCaptureVerdict::Chokepoint,
        reason: "#353's `chars().take(512)`, now behind the surface tag",
    },
    AuditedCaptures {
        file: CHOKEPOINT,
        function: "recorded_line_excerpt",
        captures: &[(".lines().take(", 1)],
        verdict: RawCaptureVerdict::Chokepoint,
        reason: "the serial-console `lines().take(n)`",
    },
    AuditedCaptures {
        file: "external_actions.rs",
        function: "run_authorized_rest_action",
        captures: &[("from_utf8_lossy(", 1)],
        verdict: RawCaptureVerdict::RoutedThroughChokepoint,
        reason:
            "the original #526 leak: raw upstream HTTP response -> recorded_http_excerpt(RestResponse) \
             -> response_excerpt. Held by recorded_rest_evidence_never_carries_bearer_material. The \
             ONE decode here is the response body read; a second one would be a new capture and is \
             counted as such.",
    },
    AuditedCaptures {
        file: "docker_backend.rs",
        function: "exec_or_attach",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::RoutedThroughChokepoint,
        reason: "stdout and stderr of the workload's own process -> IsolationExecOutcome.message \
                 -> GovernedWorkloadOutcome.output -> recorded_value(GovernedWorkloadOutput). Held \
                 by no_recorded_evidence_surface_emits_bearer_material's GovernedWorkloadOutput \
                 arm.",
    },
    AuditedCaptures {
        file: "local_process_backend.rs",
        function: "run_confined",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::RoutedThroughChokepoint,
        reason: "stdout and stderr on the same path as docker_backend::exec_or_attach, for the \
                 local-process backend. The `log_lines` copy it also keeps has no production \
                 reader; a caller added to `collect_logs` must route through recorded_value.",
    },
    AuditedCaptures {
        file: "firecracker_guest_exec.rs",
        function: "read_bounded_line",
        captures: &[("from_utf8(", 1)],
        verdict: RawCaptureVerdict::RoutedThroughChokepoint,
        reason: "guest stream frames -> ingest_guest_frame, which deserializes and sweeps in one \
                 step. Held by the_host_sweeps_guest_supplied_frames_it_ingests.",
    },
    AuditedCaptures {
        file: "backends.rs",
        function: "parse",
        captures: &[("from_utf8(", 2)],
        verdict: RawCaptureVerdict::RoutedThroughChokepoint,
        reason: "TWO DISTINCT `fn parse` bodies share this row, one each: the guest agent \
                 handshake (no free text) and the guest RPC start response, whose \
                 message/output_excerpt/denial_reason are swept by sweep_recorded_guest_text \
                 before the host records them. The count is what stops a third `fn parse` here \
                 from inheriting the verdict.",
    },
    AuditedCaptures {
        file: "docker_backend.rs",
        function: "collect_logs",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "container logs ARE workload output, but nothing in the crate calls collect_logs \
                 outside tests, so no recorded artifact reaches them today. A production caller \
                 must route the lines through recorded_value; this row is the reminder.",
    },
    AuditedCaptures {
        file: "docker_backend.rs",
        function: "checked_docker",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "the local `docker` CLI's own stdout (a container id, an image id) and its stderr \
                 on failure. Host control plane, not the workload.",
    },
    AuditedCaptures {
        file: "docker_backend.rs",
        function: "docker_backend_readiness",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "`docker version` stdout and stderr from the host daemon.",
    },
    AuditedCaptures {
        file: "local_process_backend.rs",
        function: "local_process_backend_readiness",
        captures: &[("from_utf8_lossy(", 3)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "the host's own binaries: `unshare --version`'s stderr on failure and its stdout \
                 on success, plus each namespace probe's stderr. No workload has run yet.",
    },
    AuditedCaptures {
        file: "backends.rs",
        function: "executable_version_output",
        captures: &[("from_utf8_lossy(", 2)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "stdout and stderr of a configured host binary's `--version` banner, first line \
                 recorded into the Firecracker preflight report.",
    },
    AuditedCaptures {
        file: "backends.rs",
        function: "read_firecracker_http_response",
        captures: &[("from_utf8_lossy(", 1)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "the Firecracker API socket's answer to the worker's own hypervisor calls; \
                 recorded only inside boot-smoke failure text.",
    },
    AuditedCaptures {
        file: "management.rs",
        function: "read_http_management_request",
        captures: &[("from_utf8(", 2)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "the INBOUND management request the worker is serving: its header block and its \
                 body. It is deserialized and acted on, never recorded as evidence.",
    },
    AuditedCaptures {
        file: "external_actions.rs",
        function: "spawn_one_shot_rest_smoke_server",
        captures: &[("from_utf8_lossy(", 1)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "a loopback smoke server reading back the request the worker itself just sent, \
                 inside one CLI smoke command. Printed as `served_request`; there is no upstream \
                 and no workload.",
    },
    AuditedCaptures {
        file: "external_actions.rs",
        function: "spawn_one_shot_network_egress_smoke_server",
        captures: &[("from_utf8_lossy(", 1)],
        verdict: RawCaptureVerdict::NotAttackerControlled,
        reason: "same shape: the payload the worker itself wrote, read back and printed as \
                 `received_payload`.",
    },
];

/// The only places outside [`CHOKEPOINT`] that a redactor marker may appear, and
/// why each one is not a second implementation.
///
/// Matched on the source TEXT rather than on a line number, so a real second
/// redactor in one of these files still fails: `fn redacted_args` is allowed,
/// `fn redact_bearer_headers` in `handlers.rs` is not.
const REDACTOR_MARKER_EXEMPTIONS: [(&str, &str, &str); 2] = [
    (
        "handlers.rs",
        "fn redacted_args",
        "masks the PROMPT argument by index. It knows nothing about bearer material and is not a \
         redaction of it — the credential redaction on that same argv is recorded_argv's.",
    ),
    (
        "x402_client.rs",
        "pub(crate) use crate::recorded_evidence::",
        "a #[cfg(test)] re-export so #353's eight pure-function tests keep their names while \
         exercising the shared implementation. A re-export is not a copy.",
    ),
];

/// Read every recording source of this crate, once.
///
/// Flat on purpose, and asserted flat: `agent-worker/src` has no
/// subdirectories today, and a recursive walk would hide the day it grows one.
/// A `src/families/` added tomorrow would be exactly the place a new excerpt
/// path lands, so the audit stops rather than silently skipping it.
fn recording_sources() -> Vec<(String, String)> {
    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&source_dir).expect("read the agent-worker source directory") {
        let path = entry.expect("read an agent-worker source entry").path();
        assert!(
            !path.is_dir(),
            "agent-worker/src gained the subdirectory {}; the recorded-evidence audit only reads \
             the flat directory and would skip everything inside it",
            path.display()
        );
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_recording_source(name) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read an agent-worker source file");
        sources.push((name.to_string(), source));
    }
    sources.sort();
    sources
}

fn real_tree_raw_captures() -> Vec<RawCaptureSite> {
    recording_sources()
        .iter()
        .flat_map(|(name, source)| scan_raw_captures(name, source))
        .collect()
}

/// `(file, fn)` → `idiom` → number of occurrences. The unit the audit signs off
/// on, on both sides of the comparison.
type CaptureCounts = BTreeMap<(String, String), BTreeMap<&'static str, usize>>;

fn counts_of(sites: &[RawCaptureSite]) -> CaptureCounts {
    let mut counts: CaptureCounts = BTreeMap::new();
    for site in sites {
        *counts
            .entry((site.file.clone(), site.function.clone()))
            .or_default()
            .entry(site.idiom)
            .or_default() += 1;
    }
    counts
}

fn audited_capture_counts() -> CaptureCounts {
    let mut counts: CaptureCounts = BTreeMap::new();
    for row in RAW_CAPTURE_AUDIT {
        let entry = counts
            .entry((row.file.to_string(), row.function.to_string()))
            .or_default();
        for (idiom, count) in row.captures {
            *entry.entry(*idiom).or_default() += *count;
        }
    }
    counts
}

/// Everything the tree does that the table does not account for: a new file, a
/// new function, a new IDIOM inside an already-audited function, or MORE
/// occurrences of an already-audited idiom than were signed off.
///
/// The last two are the finding this key widening exists for. Under the old
/// `(file, fn)` key both were silently blessed.
///
/// Takes the sites rather than the counts so the failure can NAME the lines a
/// reader has to go and look at.
fn captures_beyond_the_audit(sites: &[RawCaptureSite], audited: &CaptureCounts) -> Vec<String> {
    let empty = BTreeMap::new();
    let mut beyond = Vec::new();
    for ((file, function), idioms) in counts_of(sites) {
        let signed_off = audited
            .get(&(file.clone(), function.clone()))
            .unwrap_or(&empty);
        for (idiom, found) in idioms {
            let allowed = signed_off.get(idiom).copied().unwrap_or(0);
            if found > allowed {
                let where_at = sites
                    .iter()
                    .filter(|site| {
                        site.key() == (file.as_str(), function.as_str()) && site.idiom == idiom
                    })
                    .map(RawCaptureSite::location)
                    .collect::<Vec<_>>();
                beyond.push(format!(
                    "{idiom:?} appears {found} time(s), audited for {allowed}, at: {}",
                    where_at.join(", ")
                ));
            }
        }
    }
    beyond
}

/// Everything the table accounts for that the tree no longer does. A stale row
/// or a stale COUNT is a place a future capture could hide behind a verdict
/// nobody wrote for it.
fn audit_rows_beyond_the_tree(sites: &[RawCaptureSite], audited: &CaptureCounts) -> Vec<String> {
    let observed = counts_of(sites);
    let empty = BTreeMap::new();
    let mut stale = Vec::new();
    for ((file, function), idioms) in audited {
        let found_here = observed
            .get(&(file.clone(), function.clone()))
            .unwrap_or(&empty);
        for (idiom, allowed) in idioms {
            let found = found_here.get(idiom).copied().unwrap_or(0);
            if found < *allowed {
                stale.push(format!(
                    "{file} :: fn {function} :: {idiom:?} audited for {allowed} but appears \
                     {found} time(s)"
                ));
            }
        }
    }
    stale
}

// ---------------------------------------------------------------------------
// The audit, aimed at the real tree
// ---------------------------------------------------------------------------

/// #526 acceptance box 3, in the form the box actually asks for: a NEW excerpt
/// path that does not go through `recorded_evidence` fails a test.
///
/// Pins nothing in particular and everything in general — it holds the ABSENCE
/// of unreviewed raw captures across the whole crate, at
/// `(file, fn, idiom, count)` granularity. Add
/// `String::from_utf8_lossy(&output[..512]).to_string()` anywhere in a recording
/// source and it fails: in a new file or a new function because no row matches,
/// and INSIDE an already-audited function because the occurrence count for that
/// idiom goes up. The second half is what the `(file, fn)` key could not do, and
/// it is exercised against the real tree by
/// [`a_capture_added_inside_an_already_audited_function_is_not_blessed_by_its_row`].
///
/// What it still cannot see is stated in this module's docs and not repeated
/// here: a recording path that never decodes matches none of the four idioms.
#[test]
fn every_raw_capture_in_the_crate_has_an_audit_verdict() {
    /// Today's tree has 27 raw-capture sites across 17 recording sources. A
    /// scan that suddenly matches a handful has broken, not shrunk — and a
    /// broken scan is indistinguishable from a clean tree, which is the exact
    /// vacuity #526 exists to stop, one level up.
    const MINIMUM_PLAUSIBLE_SITES: usize = 20;
    const MINIMUM_PLAUSIBLE_FILES: usize = 12;

    let sources = recording_sources();
    assert!(
        sources.len() >= MINIMUM_PLAUSIBLE_FILES,
        "read only {} recording sources; the scan is looking in the wrong place",
        sources.len()
    );

    let sites = real_tree_raw_captures();
    assert!(
        sites.len() >= MINIMUM_PLAUSIBLE_SITES,
        "found only {} raw-capture sites; the scan has stopped matching",
        sites.len()
    );
    // Every idiom must still match something somewhere, or it has silently
    // stopped being a search term.
    for idiom in RAW_CAPTURE_IDIOMS {
        assert!(
            sites.iter().any(|site| site.idiom == idiom),
            "idiom {idiom:?} matched nothing in the whole crate; it no longer searches for \
             anything"
        );
    }

    let unaudited = captures_beyond_the_audit(&sites, &audited_capture_counts());
    assert!(
        unaudited.is_empty(),
        "these raw captures turn observed bytes into a string with no #526 verdict recorded:\n  \
         {}\n\
         Route them through crate::recorded_evidence, or add/extend a row in RAW_CAPTURE_AUDIT \
         saying why they are not recorded evidence. A count that went UP is a new capture inside \
         an already-reviewed function, which is exactly what the row does not cover.",
        unaudited.join("\n  ")
    );
}

/// The audit table is not allowed to accumulate rows — or COUNTS — for sites
/// that no longer exist: a stale entry is a place a future capture could hide
/// behind a verdict nobody wrote for it.
///
/// This is the other direction of the same comparison, kept separate so the
/// failure message says which way the drift went.
#[test]
fn the_audit_table_has_no_rows_for_sites_that_no_longer_exist() {
    let stale = audit_rows_beyond_the_tree(&real_tree_raw_captures(), &audited_capture_counts());

    assert!(
        stale.is_empty(),
        "these audit entries no longer match any raw-capture site; delete them or lower the \
         count:\n  {}",
        stale.join("\n  ")
    );
}

/// Every row must say something, must count something, and must count something
/// the scanner actually searches for. A verdict with an empty reason is a rubber
/// stamp, and box 4 asked for the reasoning, not the tick.
///
/// The idiom check is not decoration: a row naming an idiom that is not in
/// [`RAW_CAPTURE_IDIOMS`] can never be matched, so it would show up as
/// permanently "stale" rather than as the typo it is.
#[test]
fn every_audit_row_records_a_reason_and_a_consistent_verdict() {
    for row in RAW_CAPTURE_AUDIT {
        let AuditedCaptures {
            file,
            function,
            captures,
            verdict,
            reason,
        } = row;
        assert!(
            reason.len() > 30,
            "{file} :: fn {function} has no real reason recorded"
        );
        assert!(
            !captures.is_empty(),
            "{file} :: fn {function} is audited for no captures at all"
        );
        for (idiom, count) in captures {
            assert!(
                RAW_CAPTURE_IDIOMS.contains(idiom),
                "{file} :: fn {function} audits {idiom:?}, which the scanner never searches for"
            );
            assert!(
                *count >= 1,
                "{file} :: fn {function} audits {idiom:?} zero times"
            );
        }
        assert_eq!(
            verdict == RawCaptureVerdict::Chokepoint,
            file == CHOKEPOINT,
            "{file} :: fn {function} claims the Chokepoint verdict outside the chokepoint file, \
             or the chokepoint claims something else"
        );
    }
}

/// The finding this key widening exists for, run as the exact mutation the
/// review named rather than described.
///
/// Splices one more `String::from_utf8_lossy(..)` into the REAL
/// `external_actions.rs`, immediately after the capture that
/// `run_authorized_rest_action` is already audited for — #526's original leak,
/// in the function whose row would have blessed it. Under the previous
/// `(file, fn)` key the mutated tree produced an EMPTY `unaudited` list and
/// every scan test passed.
///
/// The insertion point is taken from the scanner's own reported line rather
/// than from a text anchor, so this cannot drift out of the function it is
/// aiming at. The clean tree is asserted first, so a fixture that was broken to
/// begin with cannot be what makes the rejection true.
#[test]
fn a_capture_added_inside_an_already_audited_function_is_not_blessed_by_its_row() {
    const TARGET_FILE: &str = "external_actions.rs";
    const TARGET_FN: &str = "run_authorized_rest_action";
    const INJECTED: &str = "    let leak = String::from_utf8_lossy(&raw_headers).to_string();";

    let audited = audited_capture_counts();
    let clean_sites = real_tree_raw_captures();
    assert!(
        captures_beyond_the_audit(&clean_sites, &audited).is_empty(),
        "the clean tree must be accepted, or the rejection below proves nothing"
    );

    let existing = clean_sites
        .iter()
        .find(|site| site.key() == (TARGET_FILE, TARGET_FN))
        .expect("run_authorized_rest_action is audited for exactly one raw capture");

    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(TARGET_FILE),
    )
    .expect("read external_actions.rs");
    let mut lines = source.lines().collect::<Vec<&str>>();
    // `existing.line` is 1-based and the scanner's line numbering is the raw
    // source's, so inserting AT that index puts the new statement on the line
    // after the audited one — still inside the same function body.
    lines.insert(existing.line, INJECTED);
    let mutated = lines.join("\n");

    let reported = captures_beyond_the_audit(&scan_raw_captures(TARGET_FILE, &mutated), &audited);

    assert!(
        reported
            .iter()
            .any(|entry| entry.contains(TARGET_FN) && entry.contains("2 time(s)")),
        "a second raw capture inside {TARGET_FN} must not inherit that function's audit row; \
         reported instead: {reported:?}"
    );
    // The other functions in the same file are untouched, so the guard reports
    // the mutation and nothing else — a rejection that fired on everything would
    // be no more useful than one that fired on nothing.
    assert_eq!(
        reported.len(),
        1,
        "only the mutated function should be reported: {reported:?}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance box 2: one implementation, proved by the suite
// ---------------------------------------------------------------------------

/// The "a grep proves there is no second copy" box, run as a test instead of
/// quoted in a commit message.
///
/// Catches the mutation #526 exists to prevent structurally: copy
/// `is_bearer_header` or a `fn redact_*` into any family's file and this fails,
/// even if that copy is correct today.
#[test]
fn only_the_chokepoint_implements_a_redaction() {
    let sources = recording_sources();
    assert!(
        sources.iter().any(|(name, _)| name.as_str() == CHOKEPOINT),
        "the chokepoint file itself was not read"
    );

    let mut chokepoint_markers = 0_usize;
    let mut foreign = Vec::new();
    for (name, source) in &sources {
        for site in scan_redactors(name, source) {
            if name.as_str() == CHOKEPOINT {
                chokepoint_markers += 1;
                continue;
            }
            let exempt = REDACTOR_MARKER_EXEMPTIONS
                .iter()
                .any(|(file, text, _)| *file == name.as_str() && site.text.contains(text));
            if !exempt {
                foreign.push(site.location());
            }
        }
    }

    assert!(
        foreign.is_empty(),
        "these files outside {CHOKEPOINT} implement a redaction:\n  {}\n\
         #526 exists because a per-family copy is what let the leak survive in four builders.",
        foreign.join("\n  ")
    );
    // Non-vacuity: the scan really does match, and matches where the one
    // implementation lives.
    assert!(
        chokepoint_markers >= 6,
        "{CHOKEPOINT} matched only {chokepoint_markers} redactor markers; the scan has stopped \
         searching for anything"
    );
}

// ---------------------------------------------------------------------------
// The surface register must not drift from the enum
// ---------------------------------------------------------------------------

/// `RecordedSurface::ALL` is what the artifact test iterates. A variant declared
/// but not listed compiles, gets an artifact arm the exhaustive match forces,
/// and is NEVER EXERCISED — an assertion that exists and proves nothing, which
/// is this repo's dominant defect mode with the safety catch removed.
///
/// Pins `recorded_evidence.rs`'s `ALL` against the enum body. The mutation it
/// catches is the reachable one: `ALL`'s declared length keeps a SHORTENED list
/// from compiling, but adding a thirteenth variant — writing its
/// compile-forced artifact arm and stopping there — leaves `[Self; 12]` valid
/// and the new surface untested. That reds here and nowhere else.
#[test]
fn the_surface_register_lists_every_surface_it_declares() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(CHOKEPOINT),
    )
    .expect("read the chokepoint source");

    let register = scan_surface_register(&source);

    assert!(
        register.declared.len() >= 12,
        "read only {:?} surfaces from the enum; the parser has stopped matching",
        register.declared
    );
    // Sorted, so reordering either list is allowed and only membership is
    // pinned — a guard that also demanded an order would fail on a tidy-up and
    // be deleted for it.
    let mut declared = register.declared.clone();
    let mut listed = register.listed.clone();
    declared.sort();
    listed.sort();
    assert_eq!(
        declared, listed,
        "RecordedSurface::ALL has drifted from the enum. A surface missing from ALL still gets a \
         compile-forced artifact arm, and that arm never runs."
    );
}

// ---------------------------------------------------------------------------
// Proof that the scan can REJECT (#480's rule: a guard aimed only at a clean
// tree has never been shown to fail)
// ---------------------------------------------------------------------------

/// A new family, added the way the original defect was: with its own decode.
const BYPASSING_SOURCE: &str = r#"
fn brand_new_family_excerpt(output: &[u8]) -> String {
    String::from_utf8_lossy(&output[..512]).trim().to_string()
}
"#;

/// The same family, routed through the chokepoint.
const ROUTED_SOURCE: &str = r#"
fn brand_new_family_excerpt(output: &[u8]) -> String {
    crate::recorded_evidence::recorded_excerpt(
        crate::recorded_evidence::RecordedSurface::ToolOutput,
        output,
        512,
    )
}
"#;

/// The rejection this whole file exists for, demonstrated rather than asserted:
/// a new excerpt path that bypasses `recorded_evidence` is SEEN, and the same
/// path routed through it is not.
///
/// The pair matters. A rejection with no paired acceptance can be a fixture that
/// was broken to begin with.
#[test]
fn the_scan_sees_a_new_family_that_decodes_for_itself_and_not_one_that_does_not() {
    let bypassing = scan_raw_captures("brand_new_family.rs", BYPASSING_SOURCE);
    assert_eq!(bypassing.len(), 1, "{bypassing:?}");
    assert_eq!(bypassing[0].function, "brand_new_family_excerpt");
    assert_eq!(
        captures_beyond_the_audit(&bypassing, &audited_capture_counts()).len(),
        1,
        "the fixture must not be pre-blessed by the audit table"
    );

    let routed = scan_raw_captures("brand_new_family.rs", ROUTED_SOURCE);
    assert!(
        routed.is_empty(),
        "routing through the chokepoint must not be reported as a bypass: {routed:?}"
    );
}

/// A comment, a doc comment or a string literal that merely NAMES an idiom must
/// not be reported.
///
/// This is not hypothetical: `recorded_evidence.rs`'s own module docs quote
/// `String::from_utf8_lossy(&bytes[..limit])` as the pattern it replaced, and
/// `handlers.rs` describes the decode it used to do. A scan that counted those
/// would produce an audit table full of prose, which is how a guard stops being
/// read and then gets deleted.
#[test]
fn a_named_idiom_in_prose_is_not_a_capture_site_but_the_same_idiom_in_code_is() {
    let prose = concat!(
        "//! This used to call String::from_utf8_lossy(&bytes[..limit]).\n",
        "/// See `text.lines().take(n)` for the old shape.\n",
        "/* String::from_utf8_lossy( */\n",
        "fn documented() -> &'static str {\n",
        "    \"String::from_utf8_lossy(\"\n",
        "}\n",
    );
    assert!(
        scan_raw_captures("prose.rs", prose).is_empty(),
        "{:?}",
        scan_raw_captures("prose.rs", prose)
    );

    let code = concat!(
        "//! This used to call String::from_utf8_lossy(&bytes[..limit]).\n",
        "fn documented(bytes: &[u8]) -> String {\n",
        "    String::from_utf8_lossy(bytes).to_string()\n",
        "}\n",
    );
    let sites = scan_raw_captures("code.rs", code);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].function, "documented");
    assert_eq!(sites[0].line, 3);
}

/// `rustfmt` breaks `.chars()\n.take(512)` across lines. A line-oriented scan
/// would miss #353's own idiom in its own chokepoint, and then miss it in the
/// next family that copies it.
#[test]
fn a_line_break_inside_an_idiom_does_not_hide_it() {
    let wrapped = concat!(
        "fn wrapped(text: &str) -> String {\n",
        "    text\n",
        "        .chars()\n",
        "        .take(512)\n",
        "        .collect()\n",
        "}\n",
    );

    let sites = scan_raw_captures("wrapped.rs", wrapped);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].function, "wrapped");
    assert_eq!(sites[0].idiom, ".chars().take(");
}

/// A capture inside a `#[cfg(test)]` item is a test fixture, not a recording
/// path, and `external_actions.rs` keeps 2000 lines of them in the same file as
/// the families they test. Blanking them is what keeps the audit table readable
/// — and the same capture outside the gate must still be reported, or the
/// blanking would be a hole rather than a filter.
#[test]
fn a_capture_behind_a_cfg_test_gate_is_not_a_recording_path_but_one_beside_it_is() {
    let gated = concat!(
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn fixture(bytes: &[u8]) -> String {\n",
        "        String::from_utf8_lossy(bytes).to_string()\n",
        "    }\n",
        "}\n",
    );
    assert!(
        scan_raw_captures("gated.rs", gated).is_empty(),
        "{:?}",
        scan_raw_captures("gated.rs", gated)
    );

    let both = format!(
        "{}{}",
        concat!(
            "fn production(bytes: &[u8]) -> String {\n",
            "    String::from_utf8_lossy(bytes).to_string()\n",
            "}\n",
        ),
        gated
    );
    let sites = scan_raw_captures("both.rs", &both);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].function, "production");
}

/// A second redactor is reported wherever it is put, and an ordinary function is
/// not.
#[test]
fn the_redactor_scan_sees_a_second_implementation_and_not_an_ordinary_function() {
    let copied = concat!(
        "fn redact_bearer_headers(text: &str) -> String {\n",
        "    text.to_string()\n",
        "}\n",
    );
    let sites = scan_redactors("some_family.rs", copied);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(
        !REDACTOR_MARKER_EXEMPTIONS
            .iter()
            .any(|(file, text, _)| *file == sites[0].file && sites[0].text.contains(text)),
        "a copied redactor must not fall under an exemption: {:?}",
        sites[0]
    );

    let ordinary = "fn record_metadata(value: &str) -> String { value.to_string() }\n";
    assert!(
        scan_redactors("some_family.rs", ordinary).is_empty(),
        "{:?}",
        scan_redactors("some_family.rs", ordinary)
    );
}

/// The register parser must actually notice a missing entry, or
/// `the_surface_register_lists_every_surface_it_declares` is a test that can
/// only ever pass.
#[test]
fn the_register_scan_sees_a_variant_that_all_forgot() {
    let drifted = concat!(
        "pub(crate) enum RecordedSurface {\n",
        "    /// doc\n",
        "    ToolOutput,\n",
        "    CliOutput,\n",
        "    RestResponse,\n",
        "}\n",
        "impl RecordedSurface {\n",
        "    #[cfg(test)]\n",
        "    pub(crate) const ALL: [Self; 2] = [\n",
        "        Self::ToolOutput,\n",
        "        Self::CliOutput,\n",
        "    ];\n",
        "}\n",
    );

    let register = scan_surface_register(drifted);

    assert_eq!(
        register.declared,
        ["ToolOutput", "CliOutput", "RestResponse"]
    );
    assert_eq!(register.listed, ["ToolOutput", "CliOutput"]);
    assert_ne!(
        register.declared, register.listed,
        "the drifted fixture must be seen as drifted"
    );

    let aligned = drifted.replace(
        "        Self::CliOutput,\n",
        "        Self::CliOutput,\n        Self::RestResponse,\n",
    );
    let aligned = scan_surface_register(&aligned);
    assert_eq!(aligned.declared, aligned.listed);
}

/// `is_recording_source` decides what the audit is allowed to ignore. If it ever
/// starts skipping a production file, every guard above goes quiet at once.
#[test]
fn only_test_modules_are_outside_the_audit() {
    assert!(is_recording_source("external_actions.rs"));
    assert!(is_recording_source(CHOKEPOINT));
    assert!(!is_recording_source("external_actions_target_test.rs"));
    assert!(!is_recording_source(
        "recorded_evidence_scan_test_support.rs"
    ));
    assert!(!is_recording_source("Cargo.toml"));
}

/// The comment stripper must not swallow live code after a `*/` or a quote,
/// which is how a source-reading guard turns correct sites red and gets deleted
/// rather than fixed (#480 hit exactly this).
#[test]
fn blanking_comments_and_literals_preserves_the_code_around_them() {
    let source = "let a = /* \" */ 1; let b = \"/*\"; let c = 2;\n";

    let code = code_only(source);

    assert_eq!(code.len(), source.len(), "line/column offsets must survive");
    assert!(code.contains("let a ="), "{code:?}");
    assert!(code.contains("let c = 2;"), "{code:?}");
    assert!(!code.contains('"'), "{code:?}");
}

/// A `RedactorSite`'s reported text comes from the RAW source, so a failure
/// shows what was found. Blanked text would print a row of spaces and teach the
/// reader nothing.
#[test]
fn a_reported_redactor_site_shows_the_real_source_line() {
    let source = "fn redact_everything(text: &str) -> String { text.to_string() }\n";

    let sites: Vec<RedactorSite> = scan_redactors("family.rs", source);

    assert_eq!(sites.len(), 1);
    assert!(
        sites[0].location().contains("fn redact_everything"),
        "{sites:?}"
    );
}
