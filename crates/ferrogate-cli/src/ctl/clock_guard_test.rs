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
//! three of that crate's own files, by `include_str!`. It cannot cover this
//! tree, and the reason recorded here used to be "a crate cannot `include_str!`
//! another crate's sources without a fragile relative path" — which is wrong on
//! its face, since that same test file `include_str!`s `../../../docs/` sixty
//! lines away. The real reason is narrower and is the one worth recording:
//! **`include_str!` cannot walk a directory.** A guard over "every module in
//! `ctl/`" has to read the tree at run time, and reading it at run time means
//! rooting the walk at `CARGO_MANIFEST_DIR` — which is this crate's manifest,
//! not that one's. The split follows the manifest, not the language.
//!
//! `crates/ferrogate-cli/src/ctl/` is precisely where a receipt is assembled,
//! rendered and printed, so a guard whose file list stops at the crate boundary
//! stops one file short of the place the defect would be written. This module
//! closes that gap from this side, with two walks:
//!
//! * [`the_ctl_tree_reads_no_local_clock`] — no local clock is *read* here.
//! * [`no_ferrogate_cli_module_mints_a_client_sent_at`] — and no module here
//!   *launders* a reading that was already taken, which is the mutation the
//!   clock scan structurally cannot see.

/// Every spelling of "read the wall clock" that reaches a `u64` of Unix
/// seconds, which is the shape the audit field takes.
///
/// It is a list and not a single needle because the obvious mutation is not
/// `SystemTime::now()`. `UNIX_EPOCH.elapsed()` produces the identical `u64`
/// with zero new dependencies and never spells `now()`; `chrono::Utc::now()`
/// is a zero-`Cargo.toml` bypass specifically, because `chrono` is already a
/// direct dependency of this crate. Both are on the list for that reason.
///
/// **Assembled at run time, from halves.** The walks below cover this file too,
/// and a needle written as one literal would make this list its own violation —
/// which is exactly the pressure that produces a `*_test.rs` exemption, and an
/// exemption for test files exempts the code most likely to normalise the
/// defect. Splitting the string is the cheaper answer and costs nothing a reader
/// has to remember.
fn clock_reads() -> [String; 5] {
    [
        format!("{}{}", "SystemTime", "::now()"),
        format!("{}{}", "Instant", "::now()"),
        format!("{}{}", "Utc", "::now()"),
        format!("{}{}", "Local", "::now()"),
        format!("{}{}", "UNIX_EPOCH", ".elapsed()"),
    ]
}

/// Which of [`clock_reads`] a line contains, if any.
///
/// Factored out so [`the_matcher_itself_detects_a_clock_read`] can feed it a
/// line that *must* match. A file-count floor proves the walk; only a positive
/// control proves the detector.
fn clock_read_in(line: &str) -> Option<String> {
    clock_reads()
        .into_iter()
        .find(|needle| line.contains(needle))
}

/// Walk a directory's shipped `.rs` modules and hand each line to `visit`,
/// returning how many files were read.
///
/// Comment lines are stripped before `visit` sees them: this tree documents the
/// rules in prose that quotes the very calls the guards look for, and a guard a
/// doc comment can trip (or defeat) is not a guard.
fn walk_modules(root: &std::path::Path, mut visit: impl FnMut(&str, &str, &str)) -> usize {
    let mut files_scanned = 0usize;
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("the scanned directory is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unnamed>")
                .to_string();
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
                visit(&name, &enclosing, trimmed);
            }
        }
    }
    files_scanned
}

/// The detector the two walks below rely on actually fires.
///
/// Pins: [`clock_read_in`] recognising each spelling in [`clock_reads`].
///
/// Catches: the mutation that makes every guard in this file green forever —
/// changing a needle to something no Rust source contains (a trailing semicolon
/// on the call is the cheap one, since real call sites appear inside larger
/// expressions). Both walks assert an **empty** result set, so neither can tell
/// "nothing violates the rule" from "the matcher matches nothing at all".
/// `the_only_local_clock_read_in_the_audit_path_is_the_one_named_for_it` in the
/// client crate does not need this: it asserts a non-empty expected set.
#[test]
fn the_matcher_itself_detects_a_clock_read() {
    for needle in clock_reads() {
        let line = format!("        let stamped = {needle}.something();");
        assert_eq!(
            clock_read_in(&line).as_deref(),
            Some(needle.as_str()),
            "the clock matcher no longer recognises '{needle}'; the guards below would then be \
             green over a tree they cannot see"
        );
    }
    assert_eq!(
        clock_read_in("        let stamped = receipt.client_clock_unverified_unix;"),
        None,
        "the matcher must not fire on an ordinary field read, or the guards below would be \
         unkeepable and would be relaxed rather than obeyed"
    );
}

/// Nothing in the CLI's `ctl` tree reads the local clock.
///
/// Pins: the absence of every spelling in [`clock_reads`] in
/// `crates/ferrogate-cli/src/ctl/`, **including that tree's own test files**.
///
/// Catches: the acceptance criterion's named defect, committed on this side of
/// the crate boundary — a renderer in `resource_cmd.rs` or `ops_cmd.rs`
/// "helpfully" stamping a receipt whose `client_sent_at` came back null, or a
/// dispatcher timing a request and folding the reading into the audit record.
/// Either produces a perfectly plausible instant that no value assertion can
/// distinguish from a server-issued one, which is why this is a source scan.
///
/// It does **not** catch a renderer that fills the field from a number already
/// on the receipt: that adds no clock read at all. That mutation belongs to
/// [`no_ferrogate_cli_module_mints_a_client_sent_at`], and the two are named
/// together so neither is mistaken for the other's coverage.
///
/// The one legitimate clock read in the whole audit path is
/// `ClientClockReading::read_local_clock`, in the client crate, named for what
/// it does — and its result travels under a header ending in `-unverified` and
/// into a receipt field named `client_clock_unverified_unix`. Nothing here
/// needs a second one.
#[test]
fn the_ctl_tree_reads_no_local_clock() {
    let ctl_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("ctl");
    let mut reads: Vec<String> = Vec::new();
    let files_scanned = walk_modules(&ctl_dir, |name, enclosing, line| {
        if let Some(needle) = clock_read_in(line) {
            reads.push(format!("{name}::{enclosing} ({needle})"));
        }
    });
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

/// No module in `ferrogate-cli` constructs a `ServerIssuedClientSentAt`.
///
/// Pins: the "only one construction site" claim in
/// `ferrogate_control_plane_client::receipt::ServerIssuedClientSentAt`'s own
/// doc, on the far side of the crate boundary that doc's premises stop at.
///
/// Catches: the receipt arm of `ctl/resource_cmd.rs` doing
///
/// ```text
/// receipt.client_identity.client_sent_at = Attested::present(ServerIssuedClientSentAt {
///     issued_at_unix: receipt.client_identity.client_clock_unverified_unix, ..
/// })
/// ```
///
/// Every field is `pub`, `Attested::present` is `pub`, and the number is already
/// on the receipt — so this **reads no clock**, is invisible to
/// [`the_ctl_tree_reads_no_local_clock`] and to the client crate's
/// `SystemTime::now()` guard, and passes `MutationReceipt::validate` because a
/// forger sets `bound_action_id` and `authority` too. The client crate's own
/// literal scan is rooted at *its* `CARGO_MANIFEST_DIR` and cannot see this
/// tree. This walk is the same rule, pointed at the second crate, and it is what
/// lets the struct doc conclude anything about "the path the CLI takes".
///
/// The whole crate is scanned, not just `ctl/`: `assets_cli.rs` and
/// `plans_cli.rs` render nothing today, but nothing stops them, and the rule is
/// about the type rather than about a directory.
#[test]
fn no_ferrogate_cli_module_mints_a_client_sent_at() {
    // Assembled at runtime so this file's own scan lines are not hits. Skipping
    // `*_test.rs` instead would exempt exactly the code most likely to normalise
    // a hand-written instant before it reaches production.
    let needle = format!("{}{}", "ServerIssuedClientSentAt", " {");
    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut literals: Vec<String> = Vec::new();
    let files_scanned = walk_modules(&source_dir, |name, enclosing, line| {
        if line.contains(&needle) {
            literals.push(format!("{name}::{enclosing}"));
        }
    });
    assert!(
        files_scanned >= 20,
        "expected the whole crate's src/ tree, scanned only {files_scanned} files in {}",
        source_dir.display()
    );
    // The matcher's control. The expected set here is empty by design, so the
    // floor above proves the walk and nothing yet proves the needle. What can be
    // shown is that it *discriminates*: it matches the opening of a struct
    // literal and not a mention of the type in a field declaration or a path.
    // Assembled the same way as `needle`, so a change to one is a change to both.
    let forged = format!(
        "        let f = {}{} issued_at_unix: 0, }};",
        "ServerIssuedClientSentAt", " {"
    );
    assert!(
        forged.contains(&needle),
        "the needle no longer matches the construction it exists to find: {forged}"
    );
    for benign in [
        "    pub client_sent_at: Attested<ServerIssuedClientSentAt>,",
        "    use ferrogate_control_plane_client::receipt::ServerIssuedClientSentAt;",
    ] {
        assert!(
            !benign.contains(&needle),
            "the needle fires on a mere mention ({benign}), which makes this guard unkeepable \
             and it would be relaxed rather than obeyed"
        );
    }
    assert!(
        literals.is_empty(),
        "ferrogate-cli constructs a ServerIssuedClientSentAt in {literals:?}. That type is the \
         receipt's SERVER-issued instant: the only expression allowed to build one is \
         ServerIssuedClientSentAt::from_server_time, over a token a server sent. A literal here \
         needs no clock read at all — the client's own reading is already on the receipt beside \
         it — so it is invisible to every other guard in this slice, and validate() cannot tell \
         it apart because a forger fills bound_action_id and authority too"
    );
}
