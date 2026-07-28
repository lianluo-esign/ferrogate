// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Source audit + behaviour pins for the live-probe opt-in convention (#495) — every workspace example that reads credentials skips cleanly without them.

//! Two guards over every example in the workspace that reads live-service
//! credentials out of the process environment.
//!
//! **The behaviour**: [`probe_env::resolve`] is the rule itself — no
//! credentials means SKIP, half-configured means hard error — executed here
//! against synthetic environments, with no Cloudflare account and without
//! touching the process environment.
//!
//! **The drift guard**: [`scan_example`] reads each probe's own source and
//! fails when it does not skip cleanly. This is the deliberate half of #495.
//! The nine `d1_live_*` probes all exited 1 without credentials because each
//! spelled the convention out for itself, and three of the nine were added by
//! the test gate *after* the correct convention already existed in
//! `ferrogate-cloudflare/examples/r2_live_probe.rs` — copying the nearest
//! neighbour is how the drift spread, so nine corrected copies would only reset
//! the clock.
//!
//! # What the guard covers, and why that is wider than a filename
//!
//! The first version of this guard walked `d1_live_*.rs` in *this crate's*
//! `examples/` only. That is a **naming** convention, not the class: a probe
//! called something else, or living in another crate, was out of reach — and
//! the two files the convention was modelled on
//! (`ferrogate-cloudflare/examples/r2_live_probe.rs`,
//! `r2_token_live_probe.rs`) were among the ones it could not see, as was
//! `ferrogate-cloudflare/examples/d1_live_probe.rs`, which still exited 1
//! without credentials under a guard whose name said otherwise. A guard whose
//! reach is narrower than the class it claims looks like coverage and is not
//! (#480, #511).
//!
//! So the walk is now every `crates/*/examples/*.rs` in the workspace, and the
//! class is a *property of the source*: an example is a **live probe** when it
//! reads the environment (`env::var(`) or declares the shared helper. The
//! **stated limit**: an example that obtains credentials some other way — a
//! config file, `option_env!`, `std::env::vars()` — is not a live probe to this
//! scan and is not audited. That is a text scan's honest ceiling; it is written
//! here rather than implied away.
//!
//! Two conventions satisfy the class, chosen per crate by whether that crate
//! owns a copy of `examples/support/probe_env.rs`:
//!
//! * [`Convention::SharedHelper`] — the helper is *in this crate*, so a probe
//!   here has no excuse: it must go through `probe_env::opt_in` and its `None`
//!   arm must be exactly `return Ok(());`.
//! * [`Convention::CleanSkip`] — the helper is not reachable from this crate
//!   (`#[path]` is relative to the including file, so the module cannot be
//!   shared across packages without either duplicating it or reaching outside
//!   the package directory). The floor still holds: the **first** environment
//!   read is the opt-in switch and must be bound by a `let … else` that prints
//!   a notice and returns `Ok(())`. Later reads are required credentials, and a
//!   missing one is a hard error by #495's own decision.
//!
//! Following `transaction_pin_scan_test_support` (#480), the scan is a pure
//! function of `(file_name, source, convention)`, so it can be aimed at sources
//! that MUST be rejected. A guard only ever pointed at the real tree — which
//! passes — is never shown to reject anything, and cannot be told apart from a
//! guard that matches nothing at all.
//!
//! This test lives in `ferrogate-storage` because that is where the helper and
//! nine of the thirteen probes are; it reads the sources of `ferrogate-cloudflare`
//! and `ferrogate-runtime` as text and depends on neither, the same shape as
//! `ferrogate-cli/tests/workspace_skeleton.rs`. The cost is real and worth
//! naming: editing a `ferrogate-runtime` example can now redden a
//! `ferrogate-storage` test.

#[path = "../examples/support/probe_env.rs"]
mod probe_env;

use probe_env::{resolve, Outcome, OPT_IN_VAR};

// ---------------------------------------------------------------------------
// The rule, executed.
// ---------------------------------------------------------------------------

/// A fake environment: `resolve` takes its lookup as a parameter precisely so
/// this can exist. `std::env::set_var` is process-global and would make these
/// tests race each other inside the one test binary.
fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    move |name: &str| {
        owned
            .iter()
            .find(|(declared, _)| declared == name)
            .map(|(_, value)| value.clone())
    }
}

const REQUIRED: [&str; 2] = ["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_TOKEN"];

/// **The #495 defect.** With no credentials at all the probe must skip and
/// return `Ok`, so the process exits 0. Before this, every `d1_live_*` probe
/// returned `Err` here and exited 1: the first `for p in ...; do cargo run
/// --example $p; done` would have read all nine as failures on the machine of
/// any contributor without Cloudflare credentials, which is nearly all of them.
#[test]
fn a_probe_with_no_credentials_skips_instead_of_failing() {
    let outcome = resolve("probe_x", &REQUIRED, env_of(&[]))
        .expect("missing credentials must not be an error at all");
    let Outcome::Skip { notice } = outcome else {
        panic!("no credentials must produce a SKIP, not a live run");
    };
    assert!(
        notice.starts_with("probe_x: SKIP"),
        "the notice must name the probe and say SKIP (the wording the acceptance criteria use), \
         got: {notice}",
    );
    for name in std::iter::once(OPT_IN_VAR).chain(REQUIRED) {
        assert!(
            notice.contains(name),
            "the skip notice must list {name} so a reader learns what to set; got: {notice}",
        );
    }
}

/// A variable exported as an empty string is not a credential. Treating the
/// opt-in switch's empty value as "set" would send the probe into a live run
/// that dies at authentication instead of skipping.
#[test]
fn an_empty_opt_in_variable_counts_as_unset() {
    let outcome = resolve(
        "probe_x",
        &REQUIRED,
        env_of(&[
            (OPT_IN_VAR, "   "),
            ("FERROGATE_CF_API_TOKEN", "t"),
            ("FERROGATE_D1_PROXY_TOKEN", "t"),
        ]),
    )
    .expect("an empty opt-in value must skip, not error");
    assert!(
        matches!(outcome, Outcome::Skip { .. }),
        "an empty {OPT_IN_VAR} must be read as unset",
    );
}

/// **The decision #495 asks for.** Opted in but half-configured is an operator
/// mistake, not an opt-out, so it is a hard error — and the error names every
/// missing variable, not just the first one the old per-probe `required()`
/// helper happened to reach.
///
/// The alternative (skip when anything is missing) fails silently in exactly
/// the direction this repo keeps filing issues about: the gate would report a
/// green live probe that never ran.
#[test]
fn a_half_configured_environment_is_a_hard_error_not_a_skip() {
    let error = resolve("probe_x", &REQUIRED, env_of(&[(OPT_IN_VAR, "acct")]))
        .err()
        .expect("opted in with credentials missing must fail loudly, never skip");
    for missing in REQUIRED {
        assert!(
            error.contains(missing),
            "the failure must name every missing variable ({missing}); got: {error}",
        );
    }
    assert!(
        error.contains(OPT_IN_VAR),
        "the failure must tell the operator how to opt back out; got: {error}",
    );
}

/// The same rule for an exported-but-empty required variable: it is missing.
#[test]
fn an_empty_required_variable_is_missing() {
    let error = resolve(
        "probe_x",
        &REQUIRED,
        env_of(&[
            (OPT_IN_VAR, "acct"),
            ("FERROGATE_CF_API_TOKEN", ""),
            ("FERROGATE_D1_PROXY_TOKEN", "t"),
        ]),
    )
    .err()
    .expect("an empty required value must fail");
    assert!(error.contains("FERROGATE_CF_API_TOKEN"), "got: {error}");
}

/// A fully configured environment still runs, and hands back what it read.
#[test]
fn a_fully_configured_environment_is_ready_to_run_live() {
    let outcome = resolve(
        "probe_x",
        &REQUIRED,
        env_of(&[
            (OPT_IN_VAR, "acct-1"),
            ("FERROGATE_CF_API_TOKEN", "rest-token"),
            ("FERROGATE_D1_PROXY_TOKEN", "proxy-token"),
        ]),
    )
    .expect("a complete environment must not error");
    let Outcome::Ready(env) = outcome else {
        panic!("a complete environment must run the probe, not skip it");
    };
    assert_eq!(env.account_id(), "acct-1");
    assert_eq!(env.var("FERROGATE_CF_API_TOKEN"), "rest-token");
    assert_eq!(env.var("FERROGATE_D1_PROXY_TOKEN"), "proxy-token");
}

// ---------------------------------------------------------------------------
// The drift guard: a pure scan over one probe's source.
// ---------------------------------------------------------------------------

/// A way a probe departs from the shared convention.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    /// No `#[path = "support/probe_env.rs"] mod probe_env;`.
    HelperNotDeclared,
    /// `const PROBE` is absent, or names a different probe (the copy-paste
    /// failure: the skip notice and the PASS line would advertise the file the
    /// new probe was cloned from).
    ProbeNameMismatch { found: Option<String> },
    /// No `probe_env::opt_in(PROBE, ...)` call — nothing gates the run.
    OptInNotCalled,
    /// `probe_env::resolve` called directly, which lets a probe supply its own
    /// lookup and route around the opt-in switch.
    ResolveCalledDirectly { line: usize },
    /// The probe reads `std::env` itself, which is how all nine drifted.
    DirectEnvironmentRead { line: usize },
    /// `env.var(NAME)` with a non-literal name, which no static check can read.
    NonLiteralRead { line: usize },
    /// `env.var("NAME")` for a NAME the probe never declared to `opt_in`.
    UndeclaredRead { name: String, line: usize },
    /// **The #495 defect itself.** `probe_env::opt_in` was called, but what the
    /// probe does with the `None` is not `return Ok(());` — it returns `Err`,
    /// panics, `expect`s the `Option`, or exits with a code. Calling the helper
    /// is not the property; exiting **0** without credentials is.
    SkipBranchNotClean { line: usize },
    /// A probe in a crate with no reachable helper whose FIRST environment read
    /// is not gated by a `let … else` that prints a notice and returns `Ok(())`
    /// — so the probe fails rather than skips on a machine with no credentials.
    UngatedOptInRead { line: usize },
}

impl Finding {
    fn describe(&self, file: &str) -> String {
        match self {
            Finding::HelperNotDeclared => format!(
                "{file}: does not declare `#[path = \"support/probe_env.rs\"] mod probe_env;` — \
                 every live probe must take its credentials from the shared helper (#495)"
            ),
            Finding::ProbeNameMismatch { found } => format!(
                "{file}: expected `const PROBE: &str = \"<this file's stem>\";`, found {found:?} — \
                 a cloned probe would print another probe's name in its SKIP and PASS lines"
            ),
            Finding::OptInNotCalled => format!(
                "{file}: never calls `probe_env::opt_in(PROBE, ...)`, so nothing makes it skip \
                 cleanly without credentials (#495)"
            ),
            Finding::ResolveCalledDirectly { line } => format!(
                "{file}:{line}: calls `probe_env::resolve` directly; probes must go through \
                 `opt_in`, which reads the real environment"
            ),
            Finding::DirectEnvironmentRead { line } => format!(
                "{file}:{line}: reads `std::env` directly — this is exactly the drift #495 \
                 removed; declare the variable in the `opt_in` list instead"
            ),
            Finding::NonLiteralRead { line } => format!(
                "{file}:{line}: `env.var(...)` with a computed name; use a string literal so the \
                 declaration can be checked without credentials"
            ),
            Finding::UndeclaredRead { name, line } => format!(
                "{file}:{line}: reads {name}, which is not in this probe's `opt_in` list, so a \
                 missing value would panic at runtime instead of failing the opt-in check"
            ),
            Finding::SkipBranchNotClean { line } => format!(
                "{file}:{line}: `probe_env::opt_in(PROBE, ...)` is called but its missing-credential \
                 arm is not `else {{ return Ok(()); }}` — calling the helper is not the property; \
                 the probe must EXIT 0 without credentials (#495)"
            ),
            Finding::UngatedOptInRead { line } => format!(
                "{file}:{line}: the first environment read is the opt-in switch and must be \
                 `let Ok(v) = std::env::var(\"...\") else {{ println!(\"...: SKIP ...\"); \
                 return Ok(()); }};` — without it the probe exits 1 on every machine that has no \
                 credentials, which is #495"
            ),
        }
    }
}

/// Which rule set an example is held to, decided by the crate it lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Convention {
    /// The crate owns `examples/support/probe_env.rs`, so a probe in it must go
    /// through the shared helper.
    SharedHelper,
    /// The helper is not reachable from this crate; the probe must still skip
    /// cleanly on its own first environment read.
    CleanSkip,
}

/// What the scan learned about one probe.
struct ProbeAudit {
    file: String,
    /// Whether this probe routes through `examples/support/probe_env.rs`.
    uses_helper: bool,
    /// Variable names declared in the `opt_in` call, in order.
    declared: Vec<String>,
    /// How many `env.var("...")` reads the probe makes.
    reads: usize,
    findings: Vec<Finding>,
}

/// Audit one example source, or `None` when it is not a live probe at all.
///
/// An example is a live probe when it reads the environment or declares the
/// shared helper. Everything else — a pure-compute example, a doc sample — is
/// not asked for a skip arm it has no reason to have, and the fixture
/// [`an_example_that_never_reads_the_environment_is_not_audited`] pins that
/// classification so this is an exemption with a test rather than a silent one.
///
/// Pure: `file_name` is used only for the expected `PROBE` value and messages.
fn scan_example(file_name: &str, source: &str, convention: Convention) -> Option<ProbeAudit> {
    let chars: Vec<char> = source.chars().collect();
    let classes = classify(&chars);
    let code = code_view(&chars, &classes);
    let stem = file_name.trim_end_matches(".rs");
    let mut findings = Vec::new();

    // `mod probe_env;` is an item and the `#[path]` attribute is code, so both
    // halves are read from the code view; only the path's VALUE is a literal,
    // and it is read at the offset the attribute puts it at. A doc comment that
    // merely names `support/probe_env.rs` therefore vouches for nothing, and a
    // copy of the helper next to the probe satisfies the `mod` but not the path.
    let uses_helper = code.contains("mod probe_env;");
    let raw_reads = raw_environment_reads(&code);
    // A file that names the helper anywhere in code is a probe even when it
    // never declares the module — otherwise deleting the `#[path]` line would
    // make a probe vanish from the audit instead of failing it.
    if !code.contains("probe_env") && raw_reads.is_empty() {
        return None;
    }

    if uses_helper && !declares_shared_helper_path(&chars, &classes, &code) {
        findings.push(Finding::HelperNotDeclared);
    }
    if !uses_helper && convention == Convention::SharedHelper {
        // The helper is in this very crate; reading the environment by hand
        // here is the drift #495 removed, whatever the file is called.
        findings.push(Finding::HelperNotDeclared);
    }

    let mut declared = Vec::new();
    let mut reads = 0_usize;

    if uses_helper {
        let declared_name = probe_const(&chars, &classes);
        if declared_name.as_deref() != Some(stem) {
            findings.push(Finding::ProbeNameMismatch {
                found: declared_name,
            });
        }

        // `env::` may appear only as `probe_env::`; anything else is a std::env
        // read.
        for index in match_indices(&code, "env::") {
            if is_probe_env(&code, index) {
                if code[index..].starts_with("env::resolve") {
                    findings.push(Finding::ResolveCalledDirectly {
                        line: line_of(&code, index),
                    });
                }
                continue;
            }
            findings.push(Finding::DirectEnvironmentRead {
                line: line_of(&code, index),
            });
        }

        // The call is matched without its arguments because rustfmt breaks a
        // long one over several lines; the first argument is then checked
        // separately, so the audited `const PROBE` is what actually names the
        // probe at runtime.
        match match_indices(&code, "probe_env::opt_in(").first() {
            None => findings.push(Finding::OptInNotCalled),
            Some(&start) => {
                let open = start + code[start..].find('(').expect("the call's open paren");
                let end = close_paren(&code, open);
                if !code[open + 1..end].trim_start().starts_with("PROBE,") {
                    findings.push(Finding::OptInNotCalled);
                }
                declared = literals(&chars, &classes, open..end);

                // THE POINT OF #495. `opt_in` returning `None` must end the
                // process at exit 0. A probe that calls the helper and then
                // turns the `None` back into an `Err` is byte-for-byte the
                // pre-#495 failure with an extra function call in front of it.
                match else_block(&code, end) {
                    Err(line) => findings.push(Finding::SkipBranchNotClean { line }),
                    Ok(body) => {
                        let line = line_of(&code, body.start);
                        if normalised(&code, body) != "return Ok(());" {
                            findings.push(Finding::SkipBranchNotClean { line });
                        }
                    }
                }
            }
        }

        for index in match_indices(&code, ".var(") {
            reads += 1;
            let after = index + ".var(".len();
            match literal_at(&chars, &classes, after) {
                None => findings.push(Finding::NonLiteralRead {
                    line: line_of(&code, index),
                }),
                Some(name) => {
                    if name != OPT_IN_VAR && !declared.contains(&name) {
                        findings.push(Finding::UndeclaredRead {
                            name,
                            line: line_of(&code, index),
                        });
                    }
                }
            }
        }
    } else if convention == Convention::CleanSkip && !raw_reads.is_empty() {
        // No helper is reachable, so the floor is checked directly on the
        // source: the FIRST environment read decides whether the probe runs at
        // all, and it must skip. Later reads are declared credentials whose
        // absence is a hard error, which is the same decision `resolve` makes.
        let switch = raw_reads[0];
        let open = switch + "env::var".len();
        let close = close_paren(&code, open);
        match else_block(&code, close) {
            Err(line) => findings.push(Finding::UngatedOptInRead { line }),
            Ok(body) => {
                let line = line_of(&code, body.start);
                if !is_clean_skip(&normalised(&code, body)) {
                    findings.push(Finding::UngatedOptInRead { line });
                }
            }
        }
    }

    Some(ProbeAudit {
        file: file_name.to_string(),
        uses_helper,
        declared,
        reads,
        findings,
    })
}

/// `true` when the `env::` at `index` is the tail of `probe_env::`.
fn is_probe_env(code: &str, index: usize) -> bool {
    index >= 6 && &code[index - 6..index] == "probe_"
}

/// Code-view offsets of every `env::var(` that is not `probe_env::var(`, in
/// source order. This is the whole definition of "reads live credentials" that
/// a text scan can support, and the module docs say so.
fn raw_environment_reads(code: &str) -> Vec<usize> {
    match_indices(code, "env::var(")
        .into_iter()
        .filter(|index| !is_probe_env(code, *index))
        .collect()
}

/// `#[path = "support/probe_env.rs"]` present as CODE, with the path read as
/// the literal the attribute actually points at.
fn declares_shared_helper_path(chars: &[char], classes: &[Class], code: &str) -> bool {
    match_indices(code, "#[path").iter().any(|&start| {
        let end = code[start..]
            .find(']')
            .map_or(code.len(), |offset| start + offset);
        code[start..end]
            .find('"')
            .and_then(|offset| literal_at(chars, classes, start + offset))
            .is_some_and(|path| path == "support/probe_env.rs")
    })
}

/// The `{...}` body of the `else` that must follow the expression closing at
/// `close`, as code-view offsets. Only `?` and whitespace may sit between the
/// two: `Err(line)` otherwise, which is how `let env = opt_in(...)?.expect(..)`
/// — a probe that consumes the `None` some other way — is caught.
fn else_block(code: &str, close: usize) -> Result<std::ops::Range<usize>, usize> {
    let bytes = code.as_bytes();
    let line = line_of(code, close.min(code.len().saturating_sub(1)));
    let mut cursor = close + 1;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'?')
    {
        cursor += 1;
    }
    if !code[cursor.min(code.len())..].starts_with("else") {
        return Err(line);
    }
    cursor += "else".len();
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'{') {
        return Err(line);
    }
    Ok(cursor + 1..close_brace(code, cursor))
}

/// A skip arm written without the helper: it must tell the operator the probe
/// was skipped (a silent skip is indistinguishable from a run that did nothing
/// — #499/#509/#510/#511) and it must END by returning `Ok(())`, with no `?`,
/// `Err`, panic or `exit` anywhere in between.
fn is_clean_skip(body: &str) -> bool {
    const FORBIDDEN: [&str; 6] = ["?", "Err(", "panic!", "unwrap", "expect", "exit("];
    body.ends_with("return Ok(());")
        && body.contains("println!")
        && !FORBIDDEN.iter().any(|token| body.contains(token))
}

/// `range` of the code view with every run of whitespace collapsed to one
/// space, so a rustfmt line break cannot change what a block says.
fn normalised(code: &str, range: std::ops::Range<usize>) -> String {
    code[range.start.min(code.len())..range.end.min(code.len())]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The value of `const PROBE: &str = "...";`, read from code (so a commented-out
/// declaration cannot vouch for a probe that has none).
fn probe_const(chars: &[char], classes: &[Class]) -> Option<String> {
    let code = code_view(chars, classes);
    let start = match_indices(&code, "const PROBE: &str =")
        .first()
        .copied()?;
    let end = code[start..].find(';').map(|offset| start + offset)?;
    literals(chars, classes, start..end).into_iter().next()
}

/// How a character in the source reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Live code.
    Code,
    /// Inside a comment: it can neither violate a rule nor satisfy one.
    Comment,
    /// The body of a string or char literal.
    Literal,
}

/// Classify every character. Comments must not be read as code (a doc comment
/// that merely NAMES `std::env::var` is not a call) and string bodies must not
/// be read as code either (a variable name inside a SQL literal declares
/// nothing), but the literals are kept addressable because the declarations
/// this audit checks ARE string literals.
fn classify(chars: &[char]) -> Vec<Class> {
    let mut classes = vec![Class::Code; chars.len()];
    let mut index = 0_usize;
    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        match current {
            '/' if next == Some('/') => {
                while index < chars.len() && chars[index] != '\n' {
                    classes[index] = Class::Comment;
                    index += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 1_usize;
                classes[index] = Class::Comment;
                classes[index + 1] = Class::Comment;
                index += 2;
                while index < chars.len() && depth > 0 {
                    let here = chars[index];
                    let after = chars.get(index + 1).copied();
                    if here == '/' && after == Some('*') {
                        depth += 1;
                    } else if here == '*' && after == Some('/') {
                        depth -= 1;
                    } else {
                        classes[index] = Class::Comment;
                        index += 1;
                        continue;
                    }
                    classes[index] = Class::Comment;
                    classes[index + 1] = Class::Comment;
                    index += 2;
                }
            }
            'r' | 'b' if raw_hashes(chars, index).is_some() => {
                let (hashes, quote) = raw_hashes(chars, index).expect("raw string prefix");
                index = quote + 1;
                let closing: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                while index < chars.len() {
                    if starts_with(chars, index, &closing) {
                        index += closing.chars().count();
                        break;
                    }
                    classes[index] = Class::Literal;
                    index += 1;
                }
            }
            '"' => {
                index += 1;
                while index < chars.len() {
                    if chars[index] == '\\' {
                        classes[index] = Class::Literal;
                        if index + 1 < chars.len() {
                            classes[index + 1] = Class::Literal;
                        }
                        index += 2;
                        continue;
                    }
                    if chars[index] == '"' {
                        index += 1;
                        break;
                    }
                    classes[index] = Class::Literal;
                    index += 1;
                }
            }
            '\'' if char_literal_end(chars, index).is_some() => {
                let end = char_literal_end(chars, index).expect("char literal");
                for class in classes.iter_mut().take(end).skip(index + 1) {
                    *class = Class::Literal;
                }
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    classes
}

/// `(hash count, index of the opening quote)` when a raw-string prefix starts
/// here, else `None`. `b` is accepted so `br"..."` is not read as code.
fn raw_hashes(chars: &[char], index: usize) -> Option<(usize, usize)> {
    if index > 0 && (chars[index - 1].is_alphanumeric() || chars[index - 1] == '_') {
        return None;
    }
    let mut cursor = index;
    if chars[cursor] == 'b' {
        cursor += 1;
        if chars.get(cursor) != Some(&'r') {
            return None;
        }
    }
    if chars.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;
    let start = cursor;
    while chars.get(cursor) == Some(&'#') {
        cursor += 1;
    }
    if chars.get(cursor) == Some(&'"') {
        Some((cursor - start, cursor))
    } else {
        None
    }
}

/// The index of a char literal's closing quote, or `None` when this `'` opens a
/// lifetime (`'static`), which is ordinary code.
fn char_literal_end(chars: &[char], index: usize) -> Option<usize> {
    if chars.get(index + 1) == Some(&'\\') {
        return (index + 2..chars.len().min(index + 8)).find(|i| chars[*i] == '\'');
    }
    if chars.get(index + 2) == Some(&'\'') {
        return Some(index + 2);
    }
    None
}

fn starts_with(chars: &[char], index: usize, needle: &str) -> bool {
    needle
        .chars()
        .enumerate()
        .all(|(offset, wanted)| chars.get(index + offset) == Some(&wanted))
}

/// The source with comments and literal bodies blanked, one character in for
/// one character out so indices and line numbers survive.
fn code_view(chars: &[char], classes: &[Class]) -> String {
    chars
        .iter()
        .zip(classes)
        .map(|(character, class)| match class {
            Class::Code => *character,
            _ if *character == '\n' => '\n',
            _ => ' ',
        })
        .collect()
}

/// The body of the string literal whose opening quote sits at `index`, or
/// `None` when the expression there is not a literal at all — `env.var(name)`
/// with a computed name, which no source-level check can follow.
fn literal_at(chars: &[char], classes: &[Class], index: usize) -> Option<String> {
    if chars.get(index) != Some(&'"') {
        return None;
    }
    let mut body = String::new();
    let mut cursor = index + 1;
    while cursor < chars.len() && classes[cursor] == Class::Literal {
        body.push(chars[cursor]);
        cursor += 1;
    }
    Some(body)
}

/// Every string literal body inside `range` (character indices).
fn literals(chars: &[char], classes: &[Class], range: std::ops::Range<usize>) -> Vec<String> {
    let mut found = Vec::new();
    let mut current: Option<String> = None;
    for index in range.start..range.end.min(chars.len()) {
        if classes[index] == Class::Literal {
            current.get_or_insert_with(String::new).push(chars[index]);
        } else if let Some(literal) = current.take() {
            found.push(literal);
        }
    }
    if let Some(literal) = current {
        found.push(literal);
    }
    found
}

/// Indices of every occurrence of `needle` in the code view.
///
/// Every index in this file is an index into the code view, which is pure
/// ASCII by construction — [`code_view`] emits one character per source
/// character and blanks everything that is not code, and Rust code outside
/// comments and literals is ASCII. So byte offsets, character offsets and
/// offsets into the original `chars` all coincide.
fn match_indices(haystack: &str, needle: &str) -> Vec<usize> {
    haystack
        .match_indices(needle)
        .map(|(index, _)| index)
        .collect()
}

/// The index of the `)` that closes the `(` at `open`.
fn close_paren(code: &str, open: usize) -> usize {
    let mut depth = 0_usize;
    for (offset, character) in code[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// The index of the `}` that closes the `{` at `open`. Braces inside comments
/// and string literals are blanked out of the code view, so they cannot
/// unbalance the count.
fn close_brace(code: &str, open: usize) -> usize {
    let mut depth = 0_usize;
    for (offset, character) in code[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    code.len()
}

fn line_of(code: &str, index: usize) -> usize {
    code[..index].chars().filter(|c| *c == '\n').count() + 1
}

// ---------------------------------------------------------------------------
// The scan, aimed at sources that must be rejected.
// ---------------------------------------------------------------------------

/// Every fixture below IS a live probe, so a `None` here would mean the
/// classification broke rather than that the fixture is exempt — and a
/// rejection test that had silently stopped scanning anything would pass.
fn audit(file_name: &str, source: &str, convention: Convention) -> ProbeAudit {
    scan_example(file_name, source, convention)
        .expect("every fixture in this section is a live probe")
}

/// A probe that follows the shared-helper convention, as a baseline the
/// rejection fixtures mutate one line at a time.
fn good_probe() -> String {
    r#"
//! A live probe. Mentions std::env::var("FERROGATE_D1_TENANT_ID") in prose only.
use ferrogate_storage::Thing;

#[path = "support/probe_env.rs"]
mod probe_env;

const PROBE: &str = "d1_live_777_example_probe";

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"])? else {
        return Ok(());
    };
    let account_id = env.account_id();
    let base = env.var("FERROGATE_D1_PROXY_BASE_URL");
    Ok(())
}
"#
    .to_string()
}

const GOOD: &str = "d1_live_777_example_probe.rs";

/// The skip arm as the nine probes write it. Every `SkipBranchNotClean`
/// rejection below replaces exactly this text, so the mutation under test is
/// the arm and nothing else.
const GOOD_SKIP_ARM: &str = r#"? else {
        return Ok(());
    };"#;

#[test]
fn the_scan_accepts_a_probe_that_follows_the_convention() {
    let audit = audit(GOOD, &good_probe(), Convention::SharedHelper);
    assert_eq!(
        audit.findings,
        Vec::new(),
        "the baseline fixture must pass, or the rejections below prove nothing",
    );
    assert!(audit.uses_helper);
    assert_eq!(
        audit.declared,
        vec!["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"],
        "the declared list is read out of the opt_in call",
    );
    assert_eq!(audit.reads, 1);
}

/// Comments are not code: the baseline names `std::env::var` and an undeclared
/// variable in its doc comment, and neither is a violation. Without this the
/// guard would be a grep that any prose could trip — and, symmetrically, that
/// any prose could satisfy.
#[test]
fn prose_neither_violates_nor_satisfies_a_rule() {
    let commented_declaration = good_probe().replace(
        r#"    let base = env.var("FERROGATE_D1_PROXY_BASE_URL");"#,
        "    // env.var(\"FERROGATE_D1_TENANT_ID\") is declared, honest\n    let t = env.var(\"FERROGATE_D1_TENANT_ID\");",
    );
    let audit = audit(GOOD, &commented_declaration, Convention::SharedHelper);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::UndeclaredRead { name, .. } if name == "FERROGATE_D1_TENANT_ID")),
        "a comment must not vouch for a declaration the opt_in call never made: {:?}",
        audit.findings,
    );
}

/// The #495 defect itself, as a source pattern: the probe reads the
/// environment on its own instead of going through the helper.
#[test]
fn the_scan_rejects_a_probe_that_reads_the_environment_itself() {
    let drifted = good_probe().replace(
        "    let account_id = env.account_id();",
        r#"    let account_id = std::env::var("FERROGATE_CF_ACCOUNT_ID").map_err(|_| "required")?;"#,
    );
    let audit = audit(GOOD, &drifted, Convention::SharedHelper);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::DirectEnvironmentRead { .. })),
        "a direct std::env read must be rejected: {:?}",
        audit.findings,
    );
}

#[test]
fn the_scan_rejects_a_probe_that_never_declares_the_helper() {
    let audit = audit(
        GOOD,
        &good_probe().replace("#[path = \"support/probe_env.rs\"]\nmod probe_env;\n", ""),
        Convention::SharedHelper,
    );
    assert!(
        audit.findings.contains(&Finding::HelperNotDeclared),
        "a probe that skips the shared helper must be rejected: {:?}",
        audit.findings,
    );
    assert!(
        !audit.uses_helper,
        "the module declaration is what `uses_helper` means",
    );
}

/// The `#[path]` half is read as CODE, with its value taken as the literal the
/// attribute actually points at, so prose that merely quotes the path cannot
/// stand in for the attribute. The accepting twin is the baseline, whose doc
/// comment already names `std::env::var` without tripping anything.
#[test]
fn prose_quoting_the_helper_path_does_not_declare_the_helper() {
    let prose_only = good_probe().replace(
        "#[path = \"support/probe_env.rs\"]\n",
        "//! declared via \"support/probe_env.rs\", honest\n",
    );
    assert_ne!(prose_only, good_probe(), "the mutation must have applied");
    let audit = audit(GOOD, &prose_only, Convention::SharedHelper);
    assert!(
        audit.findings.contains(&Finding::HelperNotDeclared),
        "a doc comment quoting the path must not satisfy the `#[path]` rule: {:?}",
        audit.findings,
    );
}

#[test]
fn the_scan_rejects_a_probe_that_never_gates_on_opt_in() {
    let audit = audit(
        GOOD,
        &good_probe().replace(
            r#"    let Some(env) = probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"])? else {
        return Ok(());
    };"#,
            "    let env = probe_env::resolve(PROBE, &[], |_| Some(String::new())).unwrap();",
        ),
        Convention::SharedHelper,
    );
    assert!(
        audit.findings.contains(&Finding::OptInNotCalled),
        "a probe with no opt-in gate must be rejected: {:?}",
        audit.findings,
    );
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ResolveCalledDirectly { .. })),
        "supplying a private lookup routes around the opt-in switch: {:?}",
        audit.findings,
    );
}

/// The copy-paste failure. A new probe cloned from an existing one keeps the
/// original's name, so its SKIP notice and PASS line advertise the wrong probe
/// — and a runner's log would name a probe that never ran.
#[test]
fn the_scan_rejects_a_probe_that_kept_the_name_it_was_cloned_from() {
    let audit = audit(
        "d1_live_778_new_probe.rs",
        &good_probe(),
        Convention::SharedHelper,
    );
    assert_eq!(
        audit.findings,
        vec![Finding::ProbeNameMismatch {
            found: Some("d1_live_777_example_probe".to_string()),
        }],
        "PROBE must match the file stem",
    );
}

#[test]
fn the_scan_rejects_a_read_of_an_undeclared_variable() {
    let audit = audit(
        GOOD,
        &good_probe().replace(
            r#"env.var("FERROGATE_D1_PROXY_BASE_URL")"#,
            r#"env.var("FERROGATE_D1_TENANT_ID")"#,
        ),
        Convention::SharedHelper,
    );
    assert!(
        audit.findings.iter().any(|finding| matches!(
            finding,
            Finding::UndeclaredRead { name, .. } if name == "FERROGATE_D1_TENANT_ID"
        )),
        "reading a variable the opt-in call never checked must be rejected: {:?}",
        audit.findings,
    );
}

#[test]
fn the_scan_rejects_a_computed_variable_name() {
    let audit = audit(
        GOOD,
        &good_probe().replace(
            r#"env.var("FERROGATE_D1_PROXY_BASE_URL")"#,
            "env.var(&name)",
        ),
        Convention::SharedHelper,
    );
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::NonLiteralRead { .. })),
        "a computed name defeats the static check and must be rejected: {:?}",
        audit.findings,
    );
}

// ---------------------------------------------------------------------------
// The skip arm: calling the helper is not the property.
// ---------------------------------------------------------------------------

/// **The review's mutation, as a test.** The probe calls `probe_env::opt_in`,
/// passes `PROBE`, declares every variable it reads and touches no `std::env` —
/// and turns the `None` straight back into the pre-#495 error, exiting **1**
/// with the verbatim message from the issue body. Every one of the six earlier
/// rules still passes, which is precisely why this source was accepted before
/// `SkipBranchNotClean` existed: the guard checked that the helper was CALLED
/// and never what the probe did with the answer.
///
/// Pins `scan_example`'s exact-match on the else body. Mutation caught:
/// deleting that comparison, or weakening it to "an `else` block exists".
#[test]
fn the_scan_rejects_a_probe_that_turns_the_skip_back_into_an_error() {
    let drifted = good_probe().replace(
        GOOD_SKIP_ARM,
        r#"? else {
        return Err("FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)".into());
    };"#,
    );
    assert_ne!(drifted, good_probe(), "the mutation must have applied");
    let audit = audit(GOOD, &drifted, Convention::SharedHelper);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::SkipBranchNotClean { .. })),
        "a skip arm that returns Err is exit 1 without credentials, which is #495: {:?}",
        audit.findings,
    );
}

/// The same hole at exit 101. `expect` on the `Option` consumes the `None` with
/// no `else` arm at all, so the rule has to notice an else block's ABSENCE too
/// — not only inspect one that is there.
///
/// Pins the `Err(line)` arm of [`else_block`]. Mutation caught: treating a
/// missing `else` as "nothing to check" and returning no finding.
#[test]
fn the_scan_rejects_a_probe_that_unwraps_the_missing_credential_option() {
    let drifted = good_probe().replace(
        GOOD_SKIP_ARM,
        r#"?.expect("credentials");
    let env = env;"#,
    );
    assert_ne!(drifted, good_probe(), "the mutation must have applied");
    let audit = audit(GOOD, &drifted, Convention::SharedHelper);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::SkipBranchNotClean { .. })),
        "an `expect` on the opt-in Option panics instead of skipping: {:?}",
        audit.findings,
    );
}

/// And at whatever exit code the probe likes. The arm is present and returns
/// nothing, which is why the rule is an exact match on `return Ok(());` rather
/// than a search for the particular wrong things a probe might write.
#[test]
fn the_scan_rejects_a_probe_that_exits_instead_of_skipping() {
    let drifted = good_probe().replace(
        GOOD_SKIP_ARM,
        r#"? else {
        std::process::exit(1)
    };"#,
    );
    assert_ne!(drifted, good_probe(), "the mutation must have applied");
    let audit = audit(GOOD, &drifted, Convention::SharedHelper);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::SkipBranchNotClean { .. })),
        "a non-zero exit in the skip arm is the same failure as returning Err: {:?}",
        audit.findings,
    );
}

/// The accepting twin for the three above, written the way rustfmt breaks a
/// long call: the arm still says exactly `return Ok(());` and nothing fires. A
/// rejection whose baseline could not itself pass proves only that the fixture
/// is broken.
///
/// Pins [`normalised`] and the `?`/whitespace skip in [`else_block`]. Mutation
/// caught: comparing the raw slice instead of the whitespace-collapsed one, or
/// requiring `else` to sit immediately after the closing paren.
#[test]
fn a_skip_arm_split_across_lines_by_rustfmt_is_still_accepted() {
    let wrapped = good_probe().replace(
        r#"probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"])? else {
        return Ok(());
    };"#,
        r#"probe_env::opt_in(
        PROBE,
        &["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"],
    )?
    else {
        // nothing to clean up; the helper already printed the notice
        return Ok(());
    };"#,
    );
    assert_ne!(wrapped, good_probe(), "the mutation must have applied");
    let audit = audit(GOOD, &wrapped, Convention::SharedHelper);
    assert_eq!(
        audit.findings,
        Vec::new(),
        "line breaks and comments must not change what the arm says: {:?}",
        audit.findings,
    );
}

// ---------------------------------------------------------------------------
// The floor for crates the shared helper cannot reach.
// ---------------------------------------------------------------------------

/// A probe in a crate with no copy of `examples/support/probe_env.rs`: it reads
/// the opt-in switch itself and writes the skip out by hand. This is the shape
/// of `ferrogate-cloudflare/examples/r2_live_probe.rs` — the file the whole
/// convention was modelled on, and one the first version of this guard could
/// not see.
fn good_helperless_probe() -> String {
    r#"
//! A live probe in a crate that cannot reach support/probe_env.rs.
use ferrogate_cloudflare::CloudflareClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Skip cleanly when the opt-in creds are absent (the gate sets them).
    let Ok(account_id) = std::env::var("FERROGATE_CF_ACCOUNT_ID") else {
        println!(
            "r2_777_live_probe: SKIP (set FERROGATE_CF_ACCOUNT_ID and FERROGATE_CF_API_TOKEN)"
        );
        return Ok(());
    };
    // Opted in but half-configured is a hard error, not a second opt-out.
    let token = std::env::var("FERROGATE_CF_API_TOKEN")
        .map_err(|_| "FERROGATE_CF_API_TOKEN is required once FERROGATE_CF_ACCOUNT_ID is set")?;
    println!("{account_id} {token}");
    Ok(())
}
"#
    .to_string()
}

const HELPERLESS: &str = "r2_777_live_probe.rs";

/// The accepting baseline for every rejection below, and the pin on the
/// "later reads may hard-error" half of the rule: this probe's SECOND read
/// uses `map_err(...)?` and that is correct, because by then the operator has
/// opted in. Mutation caught: applying the skip requirement to every read,
/// which would make the #495 hard-error decision unimplementable.
#[test]
fn the_scan_accepts_a_helperless_probe_that_skips_cleanly() {
    let audit = audit(HELPERLESS, &good_helperless_probe(), Convention::CleanSkip);
    assert_eq!(
        audit.findings,
        Vec::new(),
        "the helperless baseline must pass, or the rejections below prove nothing",
    );
    assert!(
        !audit.uses_helper,
        "this probe deliberately does not route through the shared module",
    );
}

/// **The `ferrogate-cloudflare/examples/d1_live_probe.rs` defect**, exactly as
/// it stood: the opt-in switch read with `map_err(...)?`, so the process exits
/// 1 with `"FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)"` on
/// every machine without credentials — the literal string quoted in #495's
/// body, in a file the old guard's directory filter could not see.
///
/// Pins the `Err(line)` arm of [`else_block`] under `Convention::CleanSkip`.
/// Mutation caught: dropping `UngatedOptInRead` and auditing only the crate
/// that owns the helper, which is where this guard started.
#[test]
fn the_scan_rejects_a_helperless_probe_that_hard_errors_without_credentials() {
    let drifted = good_helperless_probe().replace(
        r#"    let Ok(account_id) = std::env::var("FERROGATE_CF_ACCOUNT_ID") else {
        println!(
            "r2_777_live_probe: SKIP (set FERROGATE_CF_ACCOUNT_ID and FERROGATE_CF_API_TOKEN)"
        );
        return Ok(());
    };"#,
        r#"    let account_id = std::env::var("FERROGATE_CF_ACCOUNT_ID")
        .map_err(|_| "FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)")?;"#,
    );
    assert_ne!(
        drifted,
        good_helperless_probe(),
        "the mutation must have applied",
    );
    let audit = audit(HELPERLESS, &drifted, Convention::CleanSkip);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::UngatedOptInRead { .. })),
        "an opt-in switch read that returns Err is exit 1 without credentials: {:?}",
        audit.findings,
    );
}

/// A skip that says nothing is worse than no skip: a runner reads exit 0 and
/// cannot tell a probe that ran from one that never started. Same failure mode
/// as a green guard holding nothing (#499/#509/#510/#511).
///
/// Pins the `contains("println!")` clause of [`is_clean_skip`]. Mutation
/// caught: deleting that clause.
#[test]
fn the_scan_rejects_a_helperless_probe_whose_skip_is_silent() {
    let drifted = good_helperless_probe().replace(
        r#"        println!(
            "r2_777_live_probe: SKIP (set FERROGATE_CF_ACCOUNT_ID and FERROGATE_CF_API_TOKEN)"
        );
"#,
        "",
    );
    assert_ne!(
        drifted,
        good_helperless_probe(),
        "the mutation must have applied",
    );
    let audit = audit(HELPERLESS, &drifted, Convention::CleanSkip);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::UngatedOptInRead { .. })),
        "a silent skip must be rejected: {:?}",
        audit.findings,
    );
}

/// The `else` arm is there and is not a skip. Without this the rule would be
/// satisfied by the SHAPE of the statement rather than by what it does — the
/// same substitution the blocking finding caught one level up.
///
/// Pins the `ends_with("return Ok(());")` and `Err(` clauses of
/// [`is_clean_skip`]. Mutation caught: accepting any `let … else`.
#[test]
fn the_scan_rejects_a_helperless_probe_whose_else_arm_fails() {
    let drifted = good_helperless_probe().replace(
        "        return Ok(());\n    };",
        r#"        return Err("FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)".into());
    };"#,
    );
    assert_ne!(
        drifted,
        good_helperless_probe(),
        "the mutation must have applied",
    );
    let audit = audit(HELPERLESS, &drifted, Convention::CleanSkip);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::UngatedOptInRead { .. })),
        "a let-else whose else arm returns Err still exits 1: {:?}",
        audit.findings,
    );
}

/// The floor is a floor, not an alternative. The identical source in a crate
/// that owns `examples/support/probe_env.rs` is rejected: there the helper is
/// one `#[path]` away, and hand-writing the convention again is the drift #495
/// removed. The accepting twin is
/// [`the_scan_accepts_a_helperless_probe_that_skips_cleanly`] — the same bytes
/// under [`Convention::CleanSkip`] — so this rejection is about the convention
/// and cannot be a broken fixture passing for the right reason.
#[test]
fn a_hand_written_skip_is_rejected_in_the_crate_that_owns_the_helper() {
    let audit = audit(
        HELPERLESS,
        &good_helperless_probe(),
        Convention::SharedHelper,
    );
    assert!(
        audit.findings.contains(&Finding::HelperNotDeclared),
        "a crate with the helper in it must use the helper: {:?}",
        audit.findings,
    );
}

/// The classification, both ways. An example that never touches the environment
/// is not a live probe and is not asked for a skip arm it has no reason to have
/// — but one credential read makes the very same file an audited probe, and it
/// is then rejected. Without the second half the exemption would be
/// indistinguishable from a scan that classifies nothing at all, which is how a
/// widened walk goes quietly inert.
#[test]
fn an_example_becomes_audited_exactly_when_it_starts_reading_credentials() {
    let inert = r#"
//! A pure-compute example. Mentions std::env::var("FERROGATE_CF_ACCOUNT_ID") in prose.
fn main() {
    println!("{}", 2 + 2);
}
"#;
    assert!(
        scan_example("arithmetic_example.rs", inert, Convention::CleanSkip).is_none(),
        "an example that reads no credentials is not a live probe",
    );

    let now_a_probe = inert.replace(
        r#"    println!("{}", 2 + 2);"#,
        r#"    let account_id = std::env::var("FERROGATE_CF_ACCOUNT_ID").unwrap();"#,
    );
    let audit = audit("arithmetic_example.rs", &now_a_probe, Convention::CleanSkip);
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::UngatedOptInRead { .. })),
        "one credential read makes the file a live probe, and it must then skip: {:?}",
        audit.findings,
    );
}

// ---------------------------------------------------------------------------
// The scan, aimed at the real tree.
// ---------------------------------------------------------------------------

/// Every example in the workspace that reads live-service credentials skips
/// cleanly without them: the nine `d1_live_*` probes here through
/// `examples/support/probe_env.rs`, whose `None` arm is pinned to be exactly
/// `return Ok(());`, and the four in crates the helper cannot reach through a
/// hand-written skip the scan reads directly. The tenth — in any crate, under
/// any name — cannot quietly go its own way.
#[test]
fn every_example_that_reads_credentials_skips_cleanly_without_them() {
    /// Thirteen live probes today: nine here, three in
    /// `ferrogate-cloudflare/examples/`, one in `ferrogate-runtime/examples/`.
    /// Twelve means the walk has stopped finding files and the audit is passing
    /// vacuously (#480/#500).
    const MINIMUM_PROBES: usize = 13;
    /// Nine of them are the #495 conversions and must stay on the helper.
    const MINIMUM_HELPER_PROBES: usize = 9;
    /// Four are in crates with no reachable helper. Without this floor the
    /// `CleanSkip` rule set could stop matching anything and nothing would say
    /// so — the reach gap that made this guard's first version inadequate.
    const MINIMUM_HELPERLESS_PROBES: usize = 4;
    /// The nine make 36 `env.var("...")` reads today. A scan that sees almost
    /// none of them has stopped matching the read idiom, which would make the
    /// undeclared-read rule silently inert.
    const MINIMUM_READS: usize = 20;
    /// Three crates carry live probes. One means the walk collapsed back to
    /// this crate, which is exactly the narrowness being fixed.
    const MINIMUM_CRATES: usize = 3;

    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates/ directory");
    let mut crate_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(crates_dir)
        .expect("read the crates directory")
        .map(|entry| entry.expect("read a crates entry").path())
        .collect();
    crate_dirs.sort();

    let mut audits: Vec<(String, ProbeAudit)> = Vec::new();
    let mut crates_with_probes = 0_usize;
    for crate_dir in crate_dirs {
        let examples = crate_dir.join("examples");
        if !examples.is_dir() {
            continue;
        }
        // Which convention a crate is held to is mechanical: own a copy of the
        // helper and your probes must use it. `#[path]` resolves relative to
        // the including file, so a crate without one genuinely cannot reach it.
        let convention = if examples.join("support").join("probe_env.rs").is_file() {
            Convention::SharedHelper
        } else {
            Convention::CleanSkip
        };
        let crate_name = crate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a crate directory name")
            .to_string();

        // Only files directly under `examples/` are Cargo targets; `support/`
        // holds included modules, audited as part of their includer.
        let mut sources: Vec<std::path::PathBuf> = std::fs::read_dir(&examples)
            .expect("read an examples directory")
            .map(|entry| entry.expect("read an examples entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
            .collect();
        sources.sort();

        let before = audits.len();
        for path in sources {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("an example file name")
                .to_string();
            let source = std::fs::read_to_string(&path).expect("read an example source");
            if let Some(audit) = scan_example(&name, &source, convention) {
                audits.push((crate_name.clone(), audit));
            }
        }
        if audits.len() > before {
            crates_with_probes += 1;
        }
    }

    let failures = audits
        .iter()
        .flat_map(|(crate_name, audit)| {
            let label = format!("{crate_name}/examples/{}", audit.file);
            audit
                .findings
                .iter()
                .map(move |finding| finding.describe(&label))
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "every example that reads live credentials must skip cleanly without them (#495):\n  {}",
        failures.join("\n  "),
    );

    assert!(
        audits.len() >= MINIMUM_PROBES,
        "the audit read only {} live probes (expected at least {MINIMUM_PROBES}); a walk that \
         finds nothing passes vacuously",
        audits.len(),
    );
    assert!(
        crates_with_probes >= MINIMUM_CRATES,
        "live probes were found in only {crates_with_probes} crate(s) (expected at least \
         {MINIMUM_CRATES}); the walk has narrowed back to one directory",
    );

    let helper_probes = audits.iter().filter(|(_, audit)| audit.uses_helper).count();
    assert!(
        helper_probes >= MINIMUM_HELPER_PROBES,
        "only {helper_probes} probes route through the shared helper (expected at least \
         {MINIMUM_HELPER_PROBES})",
    );
    assert!(
        audits.len() - helper_probes >= MINIMUM_HELPERLESS_PROBES,
        "only {} probes are held to the hand-written skip rule (expected at least \
         {MINIMUM_HELPERLESS_PROBES}); that rule set is no longer exercised by the tree",
        audits.len() - helper_probes,
    );

    let reads: usize = audits.iter().map(|(_, audit)| audit.reads).sum();
    assert!(
        reads >= MINIMUM_READS,
        "the audit saw only {reads} `env.var(\"...\")` reads across {} probes (expected at least \
         {MINIMUM_READS}); the undeclared-read rule has stopped matching anything",
        audits.len(),
    );
    assert!(
        audits
            .iter()
            .filter(|(_, audit)| audit.uses_helper)
            .all(|(_, audit)| audit
                .declared
                .contains(&"FERROGATE_CF_API_TOKEN".to_string())),
        "every helper probe drives the REST client with `env://FERROGATE_CF_API_TOKEN`, so every \
         one must declare it — otherwise a missing token surfaces as a resolver error mid-run \
         rather than as an opt-in failure before anything is created",
    );
}
