// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The audit path's clock guard, on the side of the boundary where receipts are
//! actually rendered (issue #548).
//!
//! `ferrogate-control-plane-client`'s
//! `the_only_local_clock_read_in_the_audit_path_is_the_one_named_for_it` scans
//! three of that crate's own files. It cannot scan this one — a crate cannot
//! `include_str!` another crate's sources without a fragile relative path — and
//! `crates/ferrogate-cli/src/ctl/` is precisely where a receipt is assembled,
//! rendered and printed. A guard whose file list stops at the crate boundary
//! stops one file short of the place the defect would be written.
//!
//! This module closes that gap from this side.

/// Nothing in the CLI's `ctl` tree reads the local clock.
///
/// Pins: the absence of `SystemTime::now()` / `Instant::now()` in
/// `crates/ferrogate-cli/src/ctl/`.
///
/// Catches: the acceptance criterion's named defect, committed on this side of
/// the crate boundary — a renderer in `resource_cmd.rs` or `ops_cmd.rs`
/// "helpfully" stamping a receipt whose `client_sent_at` came back null, or a
/// dispatcher timing a request and folding the reading into the audit record.
/// Either produces a perfectly plausible instant that no value assertion can
/// distinguish from a server-issued one, which is why this is a source scan.
///
/// The one legitimate clock read in the whole audit path is
/// `ClientClockReading::read_local_clock`, in the client crate, named for what
/// it does — and its result travels under a header ending in `-unverified` and
/// into a receipt field named `client_clock_unverified_unix`. Nothing here
/// needs a second one.
///
/// Comment lines are stripped before the scan: this tree documents the rule in
/// prose that quotes the call, and a guard a doc comment can trip (or defeat) is
/// not a guard.
#[test]
fn the_ctl_tree_reads_no_local_clock() {
    let ctl_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("ctl");
    let mut reads: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;
    for entry in std::fs::read_dir(&ctl_dir).expect("crates/ferrogate-cli/src/ctl is readable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unnamed>")
            .to_string();
        // The shipped command surface only. A test may read a clock — this
        // file's own scan quotes the call it looks for, and a guard that
        // flagged itself would be a guard nobody could keep green.
        if name.ends_with("_test.rs") {
            continue;
        }
        files_scanned += 1;
        let source = std::fs::read_to_string(&path).expect("source file is UTF-8");
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
                .or_else(|| trimmed.strip_prefix("async fn "))
                .or_else(|| trimmed.strip_prefix("pub(crate) async fn "))
            {
                enclosing = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("<unnamed>")
                    .to_string();
            }
            if line.contains("SystemTime::now()") || line.contains("Instant::now()") {
                reads.push(format!("{name}::{enclosing}"));
            }
        }
    }
    // A floor, not a census: a mis-rooted scan would otherwise find nothing and
    // pass for the wrong reason.
    assert!(
        files_scanned >= 5,
        "expected the ctl tree's shipped modules, scanned only {files_scanned} files in {}",
        ctl_dir.display()
    );
    assert!(
        reads.is_empty(),
        "the CLI's ctl tree reads the local clock in {reads:?}. This is where receipts are \
         rendered, so a reading taken here is one edit away from the audit timestamp — and it \
         would look like a perfectly plausible instant. The audit instant is the server's or it \
         is null with a reason; the client's own reading is taken once, in \
         ClientClockReading::read_local_clock, and travels in a field that says it is unverified"
    );
}
