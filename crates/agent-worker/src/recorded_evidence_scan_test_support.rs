// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
//
// The pure half of the recorded-evidence source audit (#526): functions over
// `(file_name, source_text)` that report where this crate turns raw observed
// bytes into a string, where a redaction is implemented, and whether the
// `RecordedSurface` register lists every surface it declares.
//
// Why a SOURCE scan exists at all, when `recorded_evidence.rs` is already the
// one chokepoint: the type system forces a surface to be named once a helper is
// called, and the exhaustive matches in
// `external_actions_recorded_evidence_test.rs` force an artifact assertion for
// every surface that exists. Neither can force a NEW recording path to call a
// helper in the first place. That is the residual hole #526's rework named and
// did not close, and it is the exact shape of the original defect: a family
// wrote `response.chars().take(512)` itself and no test in the crate noticed.
// This scan notices. A raw decode or truncation in a recording source must
// either be routed through `recorded_evidence`, or be listed in
// `recorded_evidence_scan_test.rs`'s audit with a verdict a reviewer wrote.
//
// Keeping the analysis pure is deliberate, and copied from the `search_path`
// pin audit (#480): a guard that can only be pointed at the live tree can never
// be shown to REJECT anything, so it proves nothing about the class of defect it
// claims to stop. `recorded_evidence_scan_test.rs` aims these functions at the
// real tree AND at synthetic sources that must be rejected.
//
// This file is named `*_test_support.rs` deliberately: [`is_recording_source`]
// skips it, so the idioms it spells out as string literals are never mistaken
// for real capture sites.

/// The ways this crate has ever turned raw observed bytes or text into a string
/// that could be recorded.
///
/// Two of them are the original defect verbatim: `response.chars().take(512)`
/// (#353's subject) and `text.lines().take(n)` (the microVM serial console).
/// The decode idioms are here because a decode is the step that makes bytes
/// recordable at all — every leaking builder #526 found began with one.
///
/// Matching runs over a WHITESPACE-FREE view of the code, so `rustfmt` breaking
/// `.chars()\n.take(` across lines cannot hide a site.
pub(crate) const RAW_CAPTURE_IDIOMS: [&str; 4] = [
    "from_utf8_lossy(",
    "from_utf8(",
    ".chars().take(",
    ".lines().take(",
];

/// Identifiers that mean "this file implements a redaction".
///
/// Acceptance box 2 of #526 asks for a grep proving there is no second copy of
/// the redaction. A grep in a commit message rots the moment someone adds one;
/// this is the same grep, run by the suite, over code rather than over comments.
pub(crate) const REDACTOR_MARKERS: [&str; 4] = [
    "fn redact",
    "fn is_bearer",
    "BEARER_HEADERS",
    "REDACTED_HEADER_VALUE",
];

/// One place a recording source turns raw bytes or text into a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawCaptureSite {
    pub(crate) file: String,
    /// 1-based line of the idiom, so a failure names a place a reader can jump
    /// to.
    pub(crate) line: usize,
    /// The enclosing `fn`, which is what the audit is keyed on. A line number
    /// would rot on every unrelated edit above it; a function name only changes
    /// when the function does.
    pub(crate) function: String,
    pub(crate) idiom: &'static str,
}

impl RawCaptureSite {
    pub(crate) fn location(&self) -> String {
        format!("{}:{} in fn {}", self.file, self.line, self.function)
    }

    /// The audit key: the pair a reviewer signs off on.
    pub(crate) fn key(&self) -> (&str, &str) {
        (self.file.as_str(), self.function.as_str())
    }
}

/// One place a file implements (or looks like it implements) a redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactorSite {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) marker: &'static str,
    /// The trimmed source line, so the failure message shows what was found
    /// rather than only where.
    pub(crate) text: String,
}

impl RedactorSite {
    pub(crate) fn location(&self) -> String {
        format!(
            "{}:{} matched {:?} in: {}",
            self.file, self.line, self.marker, self.text
        )
    }
}

/// The `RecordedSurface` register, read from source: the variants the enum
/// DECLARES and the variants `RecordedSurface::ALL` LISTS.
///
/// They must agree. The exhaustive matches force an arm for every declared
/// variant, but a variant missing from `ALL` gets an arm that is never
/// EXECUTED — the artifact assertion exists and proves nothing. Nothing in the
/// type system catches that, so this does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SurfaceRegister {
    pub(crate) declared: Vec<String>,
    pub(crate) listed: Vec<String>,
}

/// Whether a file in `crates/agent-worker/src` is one that can RECORD evidence.
///
/// Test modules build throwaway captures on purpose — that is what
/// `recorded_evidence_test.rs` is for — and this support module spells the
/// idioms out as literals, so both are out of scope.
pub(crate) fn is_recording_source(file_name: &str) -> bool {
    file_name.ends_with(".rs")
        && !file_name.ends_with("_test.rs")
        && !file_name.contains("test_support")
}

/// Every raw-capture site in `source`, with the enclosing function.
///
/// The analysis runs over [`code_only`] with `#[cfg(test)]` items blanked, never
/// over the raw text. Both exclusions are load-bearing: `recorded_evidence.rs`'s
/// own module docs quote `String::from_utf8_lossy(&bytes[..limit])` as the
/// pattern it REPLACED, and `external_actions.rs` carries its test module in the
/// same file, whose loopback smoke servers decode the requests they serve. A
/// scan that counted either would be so noisy that the audit table would stop
/// being read, which is how a guard gets deleted rather than fixed.
pub(crate) fn scan_raw_captures(file_name: &str, source: &str) -> Vec<RawCaptureSite> {
    let code = blank_test_items(&code_only(source));
    let code_lines = code.lines().collect::<Vec<&str>>();
    let (dense, dense_lines) = dense_code(&code);
    let mut sites = Vec::new();
    for idiom in RAW_CAPTURE_IDIOMS {
        let mut cursor = 0_usize;
        while let Some(offset) = dense[cursor..].find(idiom) {
            let position = cursor + offset;
            let line = dense_lines[position];
            sites.push(RawCaptureSite {
                file: file_name.to_string(),
                line,
                function: enclosing_function(&code_lines, line),
                idiom,
            });
            cursor = position + 1;
        }
    }
    sites.sort_by(|left, right| (left.line, left.idiom).cmp(&(right.line, right.idiom)));
    sites
}

/// Every place `source` looks like it implements a redaction.
///
/// Unlike [`scan_raw_captures`] this deliberately does NOT blank `#[cfg(test)]`
/// items: a redactor smuggled in behind a test gate is still a second
/// implementation to keep in sync, and `recorded_evidence.rs`'s own
/// `redact_bearer_headers` is exactly such a test-gated entry point.
pub(crate) fn scan_redactors(file_name: &str, source: &str) -> Vec<RedactorSite> {
    let code = code_only(source);
    let mut sites = Vec::new();
    for (index, line) in code.lines().enumerate() {
        for marker in REDACTOR_MARKERS {
            if line.contains(marker) {
                sites.push(RedactorSite {
                    file: file_name.to_string(),
                    line: index + 1,
                    marker,
                    text: source
                        .lines()
                        .nth(index)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                });
            }
        }
    }
    sites
}

/// The declared-vs-listed `RecordedSurface` register.
///
/// Reads code with comments and string literals blanked but WITHOUT blanking
/// `#[cfg(test)]` items, because `ALL` is itself test-gated.
pub(crate) fn scan_surface_register(source: &str) -> SurfaceRegister {
    let code = code_only(source);
    SurfaceRegister {
        declared: enum_variants(&code, "enum RecordedSurface"),
        listed: listed_variants(&code, "const ALL"),
    }
}

/// The variant names of the first enum whose declaration line contains `header`.
fn enum_variants(code: &str, header: &str) -> Vec<String> {
    let lines = code.lines().collect::<Vec<&str>>();
    let Some(start) = lines.iter().position(|line| line.contains(header)) else {
        return Vec::new();
    };
    let mut variants = Vec::new();
    for line in lines.iter().skip(start + 1) {
        let trimmed = line.trim();
        if trimmed == "}" {
            break;
        }
        let Some(name) = trimmed.strip_suffix(',') else {
            continue;
        };
        if is_variant_name(name) {
            variants.push(name.to_string());
        }
    }
    variants
}

/// The `Self::Variant` entries of the first array whose declaration line
/// contains `header`.
fn listed_variants(code: &str, header: &str) -> Vec<String> {
    let lines = code.lines().collect::<Vec<&str>>();
    let Some(start) = lines.iter().position(|line| line.contains(header)) else {
        return Vec::new();
    };
    let mut variants = Vec::new();
    for line in lines.iter().skip(start + 1) {
        let trimmed = line.trim();
        if trimmed.starts_with("];") {
            break;
        }
        let Some(name) = trimmed.strip_prefix("Self::") else {
            continue;
        };
        let name = name.trim_end_matches(',');
        if is_variant_name(name) {
            variants.push(name.to_string());
        }
    }
    variants
}

/// A bare CamelCase identifier — an enum variant with no payload and no
/// discriminant. A variant that ever grows one has to teach this scan about it,
/// which is the correct place to notice.
fn is_variant_name(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.starts_with(|character: char| character.is_ascii_uppercase())
        && candidate
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// `code` with every whitespace character removed, plus a per-BYTE map back to
/// the 1-based line the byte came from.
///
/// Whitespace goes so that `rustfmt`'s line breaks cannot hide an idiom;
/// non-ASCII is folded to a single `?` so every offset stays a char boundary and
/// `find` results index the map directly.
fn dense_code(code: &str) -> (String, Vec<usize>) {
    let mut dense = String::with_capacity(code.len());
    let mut lines = Vec::with_capacity(code.len());
    let mut line = 1_usize;
    for character in code.chars() {
        if character == '\n' {
            line += 1;
            continue;
        }
        if character.is_whitespace() {
            continue;
        }
        if character.is_ascii() {
            dense.push(character);
        } else {
            dense.push('?');
        }
        lines.push(line);
    }
    (dense, lines)
}

/// The nearest `fn` declaration at or above `line`, or `<file scope>`.
fn enclosing_function(code_lines: &[&str], line: usize) -> String {
    code_lines
        .iter()
        .take(line)
        .rev()
        .find_map(|candidate| function_name(candidate))
        .unwrap_or_else(|| "<file scope>".to_string())
}

/// The name declared by a `fn` line, after stripping visibility and the `async`
/// / `const` / `unsafe` / `extern` modifiers.
fn function_name(line: &str) -> Option<String> {
    let mut rest = line.trim();
    loop {
        if let Some(tail) = rest.strip_prefix("pub(") {
            let (_, tail) = tail.split_once(')')?;
            rest = tail.trim_start();
            continue;
        }
        let stripped = ["pub ", "async ", "const ", "unsafe ", "extern ", "default "]
            .into_iter()
            .find_map(|modifier| rest.strip_prefix(modifier));
        match stripped {
            Some(tail) => rest = tail.trim_start(),
            None => break,
        }
    }
    let name = rest
        .strip_prefix("fn ")?
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

/// `code` with every `#[cfg(test)]` item blanked out, line for line.
///
/// A test module is not a recording path, and `external_actions.rs` keeps its
/// tests in the same file as the production families it tests. Both the item
/// and its attributes go; an item with no braces (a `use`, a `mod x;`) ends at
/// its semicolon.
fn blank_test_items(code: &str) -> String {
    let lines = code.lines().collect::<Vec<&str>>();
    let mut kept = lines
        .iter()
        .map(|line| (*line).to_string())
        .collect::<Vec<String>>();
    let mut index = 0_usize;
    while index < lines.len() {
        if lines[index].trim() != "#[cfg(test)]" {
            index += 1;
            continue;
        }
        kept[index].clear();
        let mut cursor = index + 1;
        while cursor < lines.len() && lines[cursor].trim_start().starts_with("#[") {
            kept[cursor].clear();
            cursor += 1;
        }
        let mut depth = 0_i32;
        let mut opened = false;
        while cursor < lines.len() {
            let line = lines[cursor];
            kept[cursor].clear();
            for character in line.chars() {
                match character {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if opened && depth <= 0 {
                break;
            }
            if !opened && line.contains(';') {
                break;
            }
            cursor += 1;
        }
        index = cursor + 1;
    }
    kept.join("\n")
}

/// `source` with every comment, string literal and char literal blanked out,
/// one character in for one character out so line numbers survive.
///
/// String literals go with the comments for the same reason #480 gave in
/// `ferrogate-storage`: an idiom spelled inside a string is no more of a capture
/// than one spelled inside a `//`, and this crate embeds raw HTTP fixtures whose
/// contents would otherwise be read as code.
///
/// Deliberately a second copy of that crate's `code_only` rather than a shared
/// dependency: `agent-worker` is a binary crate that depends on neither
/// `ferrogate-storage` nor a lexer crate, and adding either to reach a
/// test-only helper would buy a shared 150 lines at the price of a production
/// dependency edge. The duplication is stated here so the next reader knows the
/// two exist and why.
pub(crate) fn code_only(source: &str) -> String {
    let chars = source.chars().collect::<Vec<char>>();
    let mut out = String::with_capacity(source.len());
    let mut index = 0_usize;
    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        match current {
            '/' if next == Some('/') => {
                while index < chars.len() && chars[index] != '\n' {
                    out.push(' ');
                    index += 1;
                }
            }
            '/' if next == Some('*') => index = blank_block_comment(&chars, index, &mut out),
            'r' if raw_string_hashes(&chars, index).is_some() => {
                let hashes = raw_string_hashes(&chars, index).expect("raw string prefix");
                index = blank_raw_string(&chars, index, hashes, &mut out);
            }
            '"' => index = blank_string(&chars, index, &mut out),
            '\'' => index = blank_char_literal(&chars, index, &mut out),
            _ => {
                out.push(current);
                index += 1;
            }
        }
    }
    out
}

/// Blanks `/* ... */`, honouring Rust's nesting rule, and returns the index just
/// past it.
fn blank_block_comment(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut index = start + 2;
    let mut depth = 1_usize;
    out.push_str("  ");
    while index < chars.len() && depth > 0 {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        if current == '/' && next == Some('*') {
            depth += 1;
            out.push_str("  ");
            index += 2;
        } else if current == '*' && next == Some('/') {
            depth -= 1;
            out.push_str("  ");
            index += 2;
        } else {
            out.push(blank_of(current));
            index += 1;
        }
    }
    index
}

/// Blanks a `"..."` literal (including escapes) and returns the index just past
/// the closing quote.
fn blank_string(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut index = start + 1;
    out.push(' ');
    while index < chars.len() {
        let current = chars[index];
        if current == '\\' {
            out.push(' ');
            if let Some(escaped) = chars.get(index + 1) {
                out.push(blank_of(*escaped));
            }
            index += 2;
            continue;
        }
        out.push(blank_of(current));
        index += 1;
        if current == '"' {
            break;
        }
    }
    index
}

/// The number of `#`s in a raw-string prefix starting at `index`, or `None` if
/// this `r` is just an identifier character.
fn raw_string_hashes(chars: &[char], index: usize) -> Option<usize> {
    if index > 0 && (chars[index - 1].is_alphanumeric() || chars[index - 1] == '_') {
        return None;
    }
    let mut cursor = index + 1;
    while chars.get(cursor) == Some(&'#') {
        cursor += 1;
    }
    (chars.get(cursor) == Some(&'"')).then_some(cursor - index - 1)
}

/// Blanks `r#"..."#`, which has no escapes: only `"` followed by the same number
/// of `#`s closes it.
fn blank_raw_string(chars: &[char], start: usize, hashes: usize, out: &mut String) -> usize {
    let mut index = start + hashes + 2;
    for _ in 0..hashes + 2 {
        out.push(' ');
    }
    while index < chars.len() {
        if chars[index] == '"' {
            let closes = (1..=hashes).all(|offset| chars.get(index + offset) == Some(&'#'));
            if closes {
                for _ in 0..hashes + 1 {
                    out.push(' ');
                }
                return index + hashes + 1;
            }
        }
        out.push(blank_of(chars[index]));
        index += 1;
    }
    index
}

/// Blanks `'x'` / `'\n'` so that a `'"'` cannot desynchronise the string
/// tracker. A `'` that does not close within a few characters is a lifetime,
/// which is ordinary code.
fn blank_char_literal(chars: &[char], start: usize, out: &mut String) -> usize {
    let literal_len = if chars.get(start + 1) == Some(&'\\') {
        (3..=7)
            .find(|offset| chars.get(start + offset) == Some(&'\''))
            .map(|offset| offset + 1)
    } else if chars.get(start + 2) == Some(&'\'') {
        Some(3)
    } else {
        None
    };
    let Some(literal_len) = literal_len else {
        out.push('\'');
        return start + 1;
    };
    for offset in 0..literal_len {
        out.push(blank_of(chars[start + offset]));
    }
    start + literal_len
}

/// A blanked character: newlines survive so that line numbering does.
fn blank_of(character: char) -> char {
    if character == '\n' {
        '\n'
    } else {
        ' '
    }
}
