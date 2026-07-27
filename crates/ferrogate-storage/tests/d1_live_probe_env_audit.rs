// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Source audit + behaviour pins for the live-D1-probe opt-in convention (#495) — every probe skips cleanly and none reads the environment itself.

//! Two guards over the `d1_live_*` probes in `examples/`.
//!
//! **The behaviour**: [`probe_env::resolve`] is the rule itself — no
//! credentials means SKIP, half-configured means hard error — executed here
//! against synthetic environments, with no Cloudflare account and without
//! touching the process environment.
//!
//! **The drift guard**: `scan_probe` reads each probe's own source and fails
//! when it does not go through the shared helper. This is the deliberate half
//! of #495. The nine probes it covers all exited 1 without credentials because
//! each spelled the convention out for itself, and three of the nine were added
//! by the test gate *after* the correct convention already existed in
//! `ferrogate-cloudflare/examples/r2_live_probe.rs` — copying the nearest
//! neighbour is how the drift spread, so nine corrected copies would only
//! reset the clock. A tenth probe must now go through
//! `examples/support/probe_env.rs` or this test fails.
//!
//! Following `transaction_pin_scan_test_support` (#480), the scan is a pure
//! function of `(file_name, source)`, so it can be aimed at sources that MUST
//! be rejected. A guard only ever pointed at the real tree — which passes —
//! is never shown to reject anything, and cannot be told apart from a guard
//! that matches nothing at all.

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
        }
    }
}

/// What the scan learned about one probe.
struct ProbeAudit {
    file: String,
    /// Variable names declared in the `opt_in` call, in order.
    declared: Vec<String>,
    /// How many `env.var("...")` reads the probe makes.
    reads: usize,
    findings: Vec<Finding>,
}

/// Audit one probe source. Pure: `file_name` is used only for the expected
/// `PROBE` value and for messages.
fn scan_probe(file_name: &str, source: &str) -> ProbeAudit {
    let chars: Vec<char> = source.chars().collect();
    let classes = classify(&chars);
    let code = code_view(&chars, &classes);
    let stem = file_name.trim_end_matches(".rs");
    let mut findings = Vec::new();

    // `mod probe_env;` is an item, so it is read from code; the path it points
    // at is a string literal, so that half is read from the raw source. A copy
    // of the helper next to the probe would satisfy the `mod` but not the path.
    if !(code.contains("mod probe_env;") && source.contains("\"support/probe_env.rs\"")) {
        findings.push(Finding::HelperNotDeclared);
    }

    let declared_name = probe_const(&chars, &classes);
    if declared_name.as_deref() != Some(stem) {
        findings.push(Finding::ProbeNameMismatch {
            found: declared_name,
        });
    }

    // `env::` may appear only as `probe_env::`; anything else is a std::env read.
    for index in match_indices(&code, "env::") {
        if index >= 6 && code[index - 6..index].eq("probe_") {
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

    // The call is matched without its arguments because rustfmt breaks a long
    // one over several lines; the first argument is then checked separately, so
    // the audited `const PROBE` is what actually names the probe at runtime.
    let declared = match match_indices(&code, "probe_env::opt_in(").first() {
        None => {
            findings.push(Finding::OptInNotCalled);
            Vec::new()
        }
        Some(&start) => {
            let open = start + code[start..].find('(').expect("the call's open paren");
            let end = close_paren(&code, open);
            if !code[open + 1..end].trim_start().starts_with("PROBE,") {
                findings.push(Finding::OptInNotCalled);
            }
            literals(&chars, &classes, open..end)
        }
    };

    let mut reads = 0_usize;
    for index in match_indices(&code, ".var(") {
        reads += 1;
        let after = index + ".var(".len();
        match literal_at(&chars, &classes, after) {
            None => findings.push(Finding::NonLiteralRead {
                line: line_of(&code, index),
            }),
            Some(name) => {
                if name != OPT_IN_VAR && !declared.iter().any(|declared| *declared == name) {
                    findings.push(Finding::UndeclaredRead {
                        name,
                        line: line_of(&code, index),
                    });
                }
            }
        }
    }

    ProbeAudit {
        file: file_name.to_string(),
        declared,
        reads,
        findings,
    }
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
                    .chain(std::iter::repeat('#').take(hashes))
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

fn line_of(code: &str, index: usize) -> usize {
    code[..index].chars().filter(|c| *c == '\n').count() + 1
}

// ---------------------------------------------------------------------------
// The scan, aimed at sources that must be rejected.
// ---------------------------------------------------------------------------

/// A probe that follows the convention, as a baseline the rejection fixtures
/// mutate one line at a time.
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

#[test]
fn the_scan_accepts_a_probe_that_follows_the_convention() {
    let audit = scan_probe(GOOD, &good_probe());
    assert_eq!(
        audit.findings,
        Vec::new(),
        "the baseline fixture must pass, or the rejections below prove nothing",
    );
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
    let audit = scan_probe(GOOD, &commented_declaration);
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
    let audit = scan_probe(GOOD, &drifted);
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
    let audit = scan_probe(
        GOOD,
        &good_probe().replace("#[path = \"support/probe_env.rs\"]\nmod probe_env;\n", ""),
    );
    assert!(
        audit.findings.contains(&Finding::HelperNotDeclared),
        "a probe that skips the shared helper must be rejected: {:?}",
        audit.findings,
    );
}

#[test]
fn the_scan_rejects_a_probe_that_never_gates_on_opt_in() {
    let audit = scan_probe(
        GOOD,
        &good_probe().replace(
            r#"    let Some(env) = probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN", "FERROGATE_D1_PROXY_BASE_URL"])? else {
        return Ok(());
    };"#,
            "    let env = probe_env::resolve(PROBE, &[], |_| Some(String::new())).unwrap();",
        ),
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
    let audit = scan_probe("d1_live_778_new_probe.rs", &good_probe());
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
    let audit = scan_probe(
        GOOD,
        &good_probe().replace(
            r#"env.var("FERROGATE_D1_PROXY_BASE_URL")"#,
            r#"env.var("FERROGATE_D1_TENANT_ID")"#,
        ),
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
    let audit = scan_probe(
        GOOD,
        &good_probe().replace(
            r#"env.var("FERROGATE_D1_PROXY_BASE_URL")"#,
            "env.var(&name)",
        ),
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
// The scan, aimed at the real tree.
// ---------------------------------------------------------------------------

/// Every live D1 probe in `examples/` takes its credentials from the shared
/// helper, so all nine skip cleanly without credentials and all nine fail
/// loudly when half-configured — and the tenth cannot quietly go its own way.
#[test]
fn every_live_d1_probe_goes_through_the_shared_opt_in_helper() {
    /// The nine probes #495 converted. A tenth is welcome; eight means the walk
    /// has stopped finding files and the audit is passing vacuously (#480/#500).
    const MINIMUM_PROBES: usize = 9;
    /// Those nine make 36 `env.var("...")` reads today. A scan that sees almost
    /// none of them has stopped matching the read idiom, which would make the
    /// undeclared-read rule silently inert.
    const MINIMUM_READS: usize = 20;

    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut audits = Vec::new();
    for entry in std::fs::read_dir(&examples).expect("read the examples directory") {
        let path = entry.expect("read an examples entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("d1_live_") || !name.ends_with(".rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read a probe source");
        audits.push(scan_probe(name, &source));
    }

    let failures = audits
        .iter()
        .flat_map(|audit| {
            audit
                .findings
                .iter()
                .map(|finding| finding.describe(&audit.file))
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "live D1 probes must take credentials from `examples/support/probe_env.rs` (#495):\n  {}",
        failures.join("\n  "),
    );

    assert!(
        audits.len() >= MINIMUM_PROBES,
        "the audit read only {} probes (expected at least {MINIMUM_PROBES}); a walk that finds \
         nothing passes vacuously",
        audits.len(),
    );
    let reads: usize = audits.iter().map(|audit| audit.reads).sum();
    assert!(
        reads >= MINIMUM_READS,
        "the audit saw only {reads} `env.var(\"...\")` reads across {} probes (expected at least \
         {MINIMUM_READS}); the undeclared-read rule has stopped matching anything",
        audits.len(),
    );
    assert!(
        audits.iter().all(|audit| audit
            .declared
            .contains(&"FERROGATE_CF_API_TOKEN".to_string())),
        "every probe drives the REST client with `env://FERROGATE_CF_API_TOKEN`, so every probe \
         must declare it — otherwise a missing token surfaces as a resolver error mid-run rather \
         than as an opt-in failure before anything is created",
    );
}
