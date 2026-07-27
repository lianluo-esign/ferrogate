// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
//
// The pure half of the `search_path` pin audit (#239/#383/#480): a function
// over `(file_name, source_text)` that reports every Postgres transaction a
// source file opens and whether that transaction pins `search_path`. Keeping
// the analysis pure is the point of #480 -- a guard that can only be pointed at
// the live source tree can never be shown to REJECT anything, so it proves
// nothing about the class of defect it claims to stop. `async_postgres_test.rs`
// runs this over the real tree; `transaction_pin_scan_test.rs` runs it over
// synthetic sources that are known-bad.
//
// This file is named `*_test_support.rs` deliberately: `is_control_plane_source`
// skips it, so the transaction idioms and pin markers it spells out as string
// literals are never mistaken for real call sites.

/// Calls that pin `search_path` for the transaction they appear in. A
/// transaction may pin directly (`transaction_search_path_sql`) or through a
/// helper that composes the pin (`coordination_session_sql`,
/// `enter_guardrail_evidence_transaction`).
pub(crate) const PIN_MARKERS: [&str; 3] = [
    "transaction_search_path_sql",
    "coordination_session_sql",
    "enter_guardrail_evidence_transaction",
];

/// How a site opened its transaction. Both idioms count: before #480 the scan
/// knew only `Client`, so a new `build_transaction()` site could have shipped
/// unpinned with the guard still green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionOpener {
    /// `client.transaction()` -- or any `.transaction()` on a pooled client.
    Client,
    /// `client.build_transaction().read_only(true).start()`.
    Builder,
}

/// One transaction-opening site and the verdict on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransactionSite {
    pub(crate) file: String,
    /// 1-based line of the opening call, so the failure message names a place a
    /// reader can jump to.
    pub(crate) line: usize,
    pub(crate) opener: TransactionOpener,
    pub(crate) pinned: bool,
}

impl TransactionSite {
    pub(crate) fn location(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

/// Whether a file in `crates/ferrogate-storage/src` carries control-plane
/// statements at all. Test modules build their own throwaway transactions
/// against throwaway schemas, so they are out of scope -- and so is this
/// module, whose string literals name the very idioms being searched for.
pub(crate) fn is_control_plane_source(file_name: &str) -> bool {
    file_name.ends_with(".rs")
        && !file_name.ends_with("_test.rs")
        && !file_name.contains("test_support")
}

/// Every transaction `source` opens, with a pin verdict for each.
///
/// The analysis runs over [`code_only`] output, never over the raw text: a
/// comment, a doc comment or a SQL literal that merely NAMES a pin helper must
/// not be able to vouch for a transaction that never calls one (#480).
pub(crate) fn scan_source(file_name: &str, source: &str) -> Vec<TransactionSite> {
    let code = code_only(source);
    let lines = code.lines().collect::<Vec<_>>();
    let mut sites = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(opener) = transaction_opener(line) else {
            continue;
        };
        let window = lines[index..method_end(&lines, index)].join("\n");
        sites.push(TransactionSite {
            file: file_name.to_string(),
            line: index + 1,
            opener,
            pinned: PIN_MARKERS.iter().any(|marker| window.contains(marker)),
        });
    }
    sites
}

/// The idiom, if this line opens a transaction. `.build_transaction()` is
/// tested first because the builder chain is what actually opens the
/// transaction; `.transaction()` is matched with its leading dot so that a
/// receiver other than a local named `client` still counts.
fn transaction_opener(line: &str) -> Option<TransactionOpener> {
    if line.contains(".build_transaction()") {
        Some(TransactionOpener::Builder)
    } else if line.contains(".transaction()") {
        Some(TransactionOpener::Client)
    } else {
        None
    }
}

/// The end of the method that opened the transaction: the first `}` at the
/// enclosing item's indentation (method bodies nest deeper). The pin may
/// legitimately come several statements in -- `initialize_schema` first takes an
/// advisory lock and creates the schema -- so the window is the whole method
/// rather than a fixed number of lines.
fn method_end(lines: &[&str], start: usize) -> usize {
    lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| matches!(line.trim_end(), "}" | "    }"))
        .map(|(index, _)| index)
        .unwrap_or(lines.len())
}

/// `source` with every comment, string literal and char literal blanked out,
/// one character in for one character out so line numbers and columns survive.
///
/// String literals are blanked along with comments for two reasons: this crate
/// embeds SQL comments (`"/* ferrogate:mcp_identity_revoke */ ..."`) that would
/// otherwise open a block comment and swallow live code, and a pin marker
/// spelled inside a SQL string is no more of a pin than one spelled inside a
/// `//` comment.
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

/// Blanks `/* ... */`, honouring Rust's nesting rule, and returns the index
/// just past it. An unterminated comment blanks to end of file, which is what a
/// compiler would reject anyway.
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

/// Blanks a `"..."` literal (including its escapes and any `\`-continued
/// newlines) and returns the index just past the closing quote.
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

/// Blanks `r#"..."#`, which has no escapes: only `"` followed by the same
/// number of `#`s closes it.
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
/// tracker (`lib.rs` quotes identifiers with exactly that literal). A `'` that
/// does not close within four characters is a lifetime, which is ordinary code.
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
