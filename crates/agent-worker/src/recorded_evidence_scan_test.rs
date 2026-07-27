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

/// EVERY raw-capture site in every recording source of this crate, with the
/// verdict on it. This is #526's audit, in the only form that cannot rot.
///
/// Keyed on `(file, enclosing fn)` rather than on a line: a line number is
/// invalidated by any edit above it, which would train the next reader to
/// re-bless the table without reading it.
const RAW_CAPTURE_AUDIT: [(&str, &str, RawCaptureVerdict, &str); 17] = [
    (
        CHOKEPOINT,
        "recorded_excerpt",
        RawCaptureVerdict::Chokepoint,
        "the decode every non-REST family used to do for itself",
    ),
    (
        CHOKEPOINT,
        "recorded_http_excerpt",
        RawCaptureVerdict::Chokepoint,
        "#353's `chars().take(512)`, now behind the surface tag",
    ),
    (
        CHOKEPOINT,
        "recorded_line_excerpt",
        RawCaptureVerdict::Chokepoint,
        "the serial-console `lines().take(n)`",
    ),
    (
        "external_actions.rs",
        "run_authorized_rest_action",
        RawCaptureVerdict::RoutedThroughChokepoint,
        "the original #526 leak: raw upstream HTTP response -> recorded_http_excerpt(RestResponse) \
         -> response_excerpt. Held by recorded_rest_evidence_never_carries_bearer_material.",
    ),
    (
        "docker_backend.rs",
        "exec_or_attach",
        RawCaptureVerdict::RoutedThroughChokepoint,
        "the workload's own stdout/stderr -> IsolationExecOutcome.message -> \
         GovernedWorkloadOutcome.output -> recorded_value(GovernedWorkloadOutput). Held by \
         no_recorded_evidence_surface_emits_bearer_material's GovernedWorkloadOutput arm.",
    ),
    (
        "local_process_backend.rs",
        "run_confined",
        RawCaptureVerdict::RoutedThroughChokepoint,
        "same path as docker_backend::exec_or_attach, for the local-process backend. The \
         `log_lines` copy it also keeps has no production reader; a caller added to \
         `collect_logs` must route through recorded_value.",
    ),
    (
        "firecracker_guest_exec.rs",
        "read_bounded_line",
        RawCaptureVerdict::RoutedThroughChokepoint,
        "guest stream frames -> ingest_guest_frame, which deserializes and sweeps in one step. \
         Held by the_host_sweeps_guest_supplied_frames_it_ingests.",
    ),
    (
        "backends.rs",
        "parse",
        RawCaptureVerdict::RoutedThroughChokepoint,
        "the guest agent handshake (no free text) and the guest RPC start response, whose \
         message/output_excerpt/denial_reason are swept by sweep_recorded_guest_text before the \
         host records them.",
    ),
    (
        "docker_backend.rs",
        "collect_logs",
        RawCaptureVerdict::NotAttackerControlled,
        "container logs ARE workload output, but nothing in the crate calls collect_logs outside \
         tests, so no recorded artifact reaches them today. A production caller must route the \
         lines through recorded_value; this row is the reminder.",
    ),
    (
        "docker_backend.rs",
        "checked_docker",
        RawCaptureVerdict::NotAttackerControlled,
        "the local `docker` CLI's own stdout (a container id, an image id) and its stderr on \
         failure. Host control plane, not the workload.",
    ),
    (
        "docker_backend.rs",
        "docker_backend_readiness",
        RawCaptureVerdict::NotAttackerControlled,
        "`docker version` output from the host daemon.",
    ),
    (
        "local_process_backend.rs",
        "local_process_backend_readiness",
        RawCaptureVerdict::NotAttackerControlled,
        "`unshare --version` and friends from the host's own binaries.",
    ),
    (
        "backends.rs",
        "executable_version_output",
        RawCaptureVerdict::NotAttackerControlled,
        "the first line of a configured host binary's `--version` banner, recorded into the \
         Firecracker preflight report.",
    ),
    (
        "backends.rs",
        "read_firecracker_http_response",
        RawCaptureVerdict::NotAttackerControlled,
        "the Firecracker API socket's answer to the worker's own hypervisor calls; recorded only \
         inside boot-smoke failure text.",
    ),
    (
        "management.rs",
        "read_http_management_request",
        RawCaptureVerdict::NotAttackerControlled,
        "the INBOUND management request the worker is serving. It is deserialized and acted on, \
         never recorded as evidence.",
    ),
    (
        "external_actions.rs",
        "spawn_one_shot_rest_smoke_server",
        RawCaptureVerdict::NotAttackerControlled,
        "a loopback smoke server reading back the request the worker itself just sent, inside one \
         CLI smoke command. Printed as `served_request`; there is no upstream and no workload.",
    ),
    (
        "external_actions.rs",
        "spawn_one_shot_network_egress_smoke_server",
        RawCaptureVerdict::NotAttackerControlled,
        "same shape: the payload the worker itself wrote, read back and printed as \
         `received_payload`.",
    ),
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

// ---------------------------------------------------------------------------
// The audit, aimed at the real tree
// ---------------------------------------------------------------------------

/// #526 acceptance box 3, in the form the box actually asks for: a NEW excerpt
/// path that does not go through `recorded_evidence` fails a test.
///
/// Pins nothing in particular and everything in general — it holds the ABSENCE
/// of unreviewed raw captures across the whole crate. The mutation it catches is
/// the one that created this issue: add
/// `String::from_utf8_lossy(&output[..512]).to_string()` to any recording source
/// and the site appears here with no audit row.
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

    let unaudited = sites
        .iter()
        .filter(|site| {
            !RAW_CAPTURE_AUDIT
                .iter()
                .any(|(file, function, _, _)| site.key() == (*file, *function))
        })
        .map(RawCaptureSite::location)
        .collect::<Vec<_>>();
    assert!(
        unaudited.is_empty(),
        "these sites turn raw observed bytes into a string with no #526 verdict recorded:\n  {}\n\
         Route them through crate::recorded_evidence, or add a row to RAW_CAPTURE_AUDIT saying \
         why they are not recorded evidence.",
        unaudited.join("\n  ")
    );
}

/// The audit table is not allowed to accumulate rows for sites that no longer
/// exist: a stale row is a place a future site could hide behind a verdict
/// nobody wrote for it.
#[test]
fn the_audit_table_has_no_rows_for_sites_that_no_longer_exist() {
    let sites = real_tree_raw_captures();

    let stale = RAW_CAPTURE_AUDIT
        .iter()
        .filter(|(file, function, _, _)| !sites.iter().any(|site| site.key() == (*file, *function)))
        .map(|(file, function, _, _)| format!("{file} :: fn {function}"))
        .collect::<Vec<_>>();

    assert!(
        stale.is_empty(),
        "these audit rows no longer match any raw-capture site; delete them:\n  {}",
        stale.join("\n  ")
    );
}

/// Every row must say something. A verdict with an empty reason is a rubber
/// stamp, and box 4 asked for the reasoning, not the tick.
#[test]
fn every_audit_row_records_a_reason_and_a_consistent_verdict() {
    for (file, function, verdict, reason) in RAW_CAPTURE_AUDIT {
        assert!(
            reason.len() > 30,
            "{file} :: fn {function} has no real reason recorded"
        );
        assert_eq!(
            verdict == RawCaptureVerdict::Chokepoint,
            file == CHOKEPOINT,
            "{file} :: fn {function} claims the Chokepoint verdict outside the chokepoint file, \
             or the chokepoint claims something else"
        );
    }
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
    assert!(
        !RAW_CAPTURE_AUDIT
            .iter()
            .any(|(file, function, _, _)| bypassing[0].key() == (*file, *function)),
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
