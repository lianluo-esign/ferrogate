// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Properties that hold the derived Postgres schema head honest --
// it must be the highest-numbered migration sql/001_init_postgres.sql actually
// applies (#511).

use super::{
    head_migration, POSTGRES_SCHEMA_LEDGER_ROWS, POSTGRES_SCHEMA_LEDGER_STATEMENTS,
    POSTGRES_SCHEMA_NAME, POSTGRES_SCHEMA_SQL, POSTGRES_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Independent readers.
//
// The const parser is a byte-offset scan. Everything below is written with
// `str` pattern methods and iterators at test time, so that agreement between
// them is evidence rather than a tautology. Two of the three pieces --
// `sql_code_only` and `insert_anchors` -- are shared by both readers, because
// "which bytes are code" is not a matter of opinion; each gets its OWN fixtures
// below (`the_test_side_stripper_*` and `the_test_side_anchor_scan_*`) so that
// sharing them does not make the readers vacuous.
// ---------------------------------------------------------------------------

/// The SQL a Postgres server would EXECUTE while loading this file: `--` to
/// end-of-line and nested `/* ... */` removed, dollar-quoted bodies it does not
/// run removed, and every quoted region (`'...'`, `E'...'`, `"..."`) copied
/// through verbatim -- a migration name lives inside one.
///
/// The earliest marker wins at every step -- one left-to-right pass, for the
/// same reason the const parser makes one: `sql/001_init_postgres.sql:1205`
/// reads `-- Gates /v1/assets/* ...` and the file has no `*/` anywhere.
///
/// Knowing every quoted spelling is not optional for a reader either. Review
/// found the const parser recognizing only `'...'`, so one apostrophe in a
/// `COPY` payload silently shifted every later quote and dropped 42 of the 64
/// ledger rows -- and this reader, knowing exactly as much, agreed with the
/// wrong answer. Agreeing with the thing you are checking, for the reason it is
/// wrong, is not a cross-check (#500).
fn sql_code_only(sql: &str) -> String {
    let mut code = String::new();
    let mut rest = sql;
    while !rest.is_empty() {
        let Some((at, marker)) = ["--", "/*", "'", "\"", "$"]
            .into_iter()
            .filter_map(|marker| rest.find(marker).map(|at| (at, marker)))
            .min()
        else {
            code.push_str(rest);
            break;
        };
        code.push_str(&rest[..at]);
        rest = &rest[at..];
        match marker {
            "--" => rest = rest.find('\n').map_or("", |end| &rest[end..]),
            "/*" => {
                let bytes = rest.as_bytes();
                let (mut depth, mut end) = (0usize, 0usize);
                while end < bytes.len() {
                    if bytes[end..].starts_with(b"/*") {
                        depth += 1;
                        end += 2;
                    } else if bytes[end..].starts_with(b"*/") {
                        depth -= 1;
                        end += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        end += 1;
                    }
                }
                assert_eq!(depth, 0, "a `/* ... */` comment is never closed: {rest}");
                rest = &rest[end..];
            }
            "$" => match dollar_tag(rest) {
                // `$1` is a positional parameter and a lone `$` is punctuation.
                None => {
                    code.push('$');
                    rest = &rest[1..];
                }
                Some(tag) => {
                    let body = &rest[tag.len()..];
                    let end = body
                        .find(tag)
                        .unwrap_or_else(|| panic!("a `{tag} ... {tag}` body is never closed"));
                    // A `DO` body RUNS as this file loads, so its statements are
                    // code; any other dollar-quoted body is a string the server
                    // stores, and a ledger row written there is never applied.
                    if ends_with_do_introducer(&code) {
                        code.push_str(&sql_code_only(&body[..end]));
                    }
                    rest = &body[end + tag.len()..];
                }
            },
            _ => {
                // `'...'`, `E'...'` and `"..."`: the contents are data, copied
                // through so that no marker inside one opens anything.
                let delimiter = marker.as_bytes()[0];
                let escapes = delimiter == b'\'' && ends_with_e_prefix(&code);
                let bytes = rest.as_bytes();
                let mut scan = 1usize;
                let end = loop {
                    assert!(
                        scan < bytes.len(),
                        "a quoted region is never closed: {rest}"
                    );
                    if escapes && bytes[scan] == b'\\' {
                        scan += 2;
                        continue;
                    }
                    if bytes[scan] == delimiter {
                        if bytes.get(scan + 1) == Some(&delimiter) {
                            scan += 2;
                            continue;
                        }
                        break scan + 1;
                    }
                    scan += 1;
                };
                code.push_str(&rest[..end]);
                rest = &rest[end..];
            }
        }
    }
    code
}

/// `$$` or `$tag$` at the front of `text`, returned with both delimiters.
fn dollar_tag(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    if bytes.get(1).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut end = 1usize;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    (bytes.get(end) == Some(&b'$')).then(|| &text[..end + 1])
}

/// True when the code emitted so far ends with the `DO` of a `DO $$ ... $$`
/// block (Postgres also allows `DO LANGUAGE plpgsql $$ ... $$`).
///
/// Deliberately decided by looking BACKWARDS over what has already been
/// emitted; the const parser decides it by parsing forwards from the keyword.
fn ends_with_do_introducer(code: &str) -> bool {
    let head = code.trim_end();
    if strip_trailing_word(head, "DO").is_some() {
        return true;
    }
    let named = head
        .trim_end_matches(|char: char| char.is_ascii_alphanumeric() || char == '_')
        .trim_end();
    strip_trailing_word(named, "LANGUAGE")
        .is_some_and(|before| strip_trailing_word(before.trim_end(), "DO").is_some())
}

/// `word` at the END of `text`, case-insensitively and as a whole word; returns
/// what precedes it.
fn strip_trailing_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let start = text.len().checked_sub(word.len())?;
    if !text.get(start..)?.eq_ignore_ascii_case(word) {
        return None;
    }
    let head = text.get(..start)?;
    (!head.ends_with(|char: char| char.is_ascii_alphanumeric() || char == '_')).then_some(head)
}

/// True when the code emitted so far ends with the `E` of an `E'...'` literal,
/// in which a backslash escapes the byte after it.
fn ends_with_e_prefix(code: &str) -> bool {
    let bytes = code.as_bytes();
    match bytes.last() {
        Some(b'E' | b'e') => !bytes[..bytes.len() - 1]
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'),
        _ => false,
    }
}

/// Byte offsets in `code` (already comment-free) at which the `INSERT` keyword
/// starts a statement -- whole word, and never inside a `'...'` literal.
fn insert_anchors(code: &str) -> Vec<usize> {
    let upper = code.to_ascii_uppercase();
    let (bytes, upper) = (code.as_bytes(), upper.as_bytes());
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut anchors = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] == b'\'' {
            at += 1;
            while at < bytes.len() {
                if bytes[at] == b'\'' {
                    if bytes.get(at + 1) == Some(&b'\'') {
                        at += 2;
                        continue;
                    }
                    at += 1;
                    break;
                }
                at += 1;
            }
            continue;
        }
        if upper[at..].starts_with(b"INSERT")
            && (at == 0 || !word(bytes[at - 1]))
            && bytes.get(at + 6).is_none_or(|byte| !word(*byte))
        {
            anchors.push(at);
            at += 6;
            continue;
        }
        at += 1;
    }
    anchors
}

/// `keyword` at the front of `text`, case-insensitively, as a whole word.
fn strip_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    if !text.get(..keyword.len())?.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &text[keyword.len()..];
    (!rest.starts_with(|char: char| char.is_ascii_alphanumeric() || char == '_')).then_some(rest)
}

/// True when a table reference resolves to the ledger: last dot-component only,
/// folded when unquoted and compared exactly when quoted, as Postgres does.
fn is_ledger_reference(reference: &str) -> bool {
    let last = reference
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .trim();
    match last.strip_prefix('"').and_then(|q| q.strip_suffix('"')) {
        Some(quoted) => quoted == "storage_schema_migrations",
        None => last.eq_ignore_ascii_case("storage_schema_migrations"),
    }
}

/// A SECOND, deliberately different reader of the same ledger. The constants are
/// produced by a byte-offset const-eval scan; this one walks `INSERT` anchors
/// and works with `str` pattern methods, at test time.
///
/// It returns ROWS, not statements: one `VALUES` clause may carry several
/// tuples, and review found that counting statements is exactly how the const
/// parser's second-tuple blind spot stayed invisible.
fn ledger_rows_by_statement_scan(sql: &str) -> Vec<(u64, String)> {
    let code = sql_code_only(sql);
    let mut rows = Vec::new();
    for anchor in insert_anchors(&code) {
        let statement = &code[anchor..];
        let Some(after_into) = strip_keyword(statement, "INSERT")
            .map(str::trim_start)
            .and_then(|rest| strip_keyword(rest, "INTO"))
            .map(str::trim_start)
        else {
            continue;
        };
        let after_only = strip_keyword(after_into, "ONLY")
            .map(str::trim_start)
            .unwrap_or(after_into);
        let Some((reference, after_table)) = after_only.split_once('(') else {
            continue;
        };
        if !is_ledger_reference(reference) {
            continue;
        }
        let (columns, after_columns) = after_table
            .split_once(')')
            .unwrap_or_else(|| panic!("unterminated ledger column list: {statement}"));
        assert_eq!(
            columns
                .chars()
                .filter(|char| !char.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase(),
            "version,name",
            "a ledger INSERT must write exactly (version, name): {statement}"
        );
        let mut rest = strip_keyword(after_columns.trim_start(), "VALUES")
            .unwrap_or_else(|| panic!("a ledger INSERT must be followed by VALUES: {statement}"));
        loop {
            let tuple_body = rest
                .trim_start()
                .strip_prefix('(')
                .unwrap_or_else(|| panic!("unparsable ledger VALUES clause: {statement}"));
            let (tuple, tail) = tuple_body
                .split_once(')')
                .unwrap_or_else(|| panic!("unterminated ledger VALUES tuple: {statement}"));
            let (version, name) = tuple
                .split_once(',')
                .unwrap_or_else(|| panic!("unparsable ledger VALUES tuple: {tuple}"));
            let version: u64 = version
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("unparsable migration version: {tuple}"));
            let name = name
                .trim()
                .strip_prefix('\'')
                .and_then(|quoted| quoted.strip_suffix('\''))
                .unwrap_or_else(|| panic!("migration name must be quoted: {tuple}"));
            rows.push((version, name.to_string()));
            rest = tail.trim_start();
            match rest.strip_prefix(',') {
                Some(next_tuple) => rest = next_tuple,
                None => break,
            }
        }
    }
    rows
}

/// A THIRD, dumber reading: every `INSERT` in the code whose table reference
/// resolves to the ledger table, however it is qualified or quoted. It knows
/// nothing about `VALUES`, so a mistake in the body parsing of either of the
/// other two readers cannot reach it.
///
/// It does resolve the table the same way the others do -- that dimension is
/// shared by all readers and the module doc says so plainly. What it adds is
/// independence of the BODY, which is where the multi-row and column-list
/// mistakes live.
fn ledger_insert_statements(sql: &str) -> usize {
    let code = sql_code_only(sql);
    insert_anchors(&code)
        .into_iter()
        .filter(|anchor| {
            let tail = code[*anchor..]
                .split_once('(')
                .map(|(reference, _)| reference)
                .unwrap_or_default();
            let Some(reference) = strip_keyword(tail, "INSERT")
                .map(str::trim_start)
                .and_then(|rest| strip_keyword(rest, "INTO"))
                .map(str::trim_start)
            else {
                return false;
            };
            let reference = strip_keyword(reference, "ONLY")
                .map(str::trim_start)
                .unwrap_or(reference);
            is_ledger_reference(reference)
        })
        .count()
}

/// The head constants must be the HIGHEST-numbered migration the SQL contains.
///
/// Pins `schema_migrations.rs`'s `POSTGRES_SCHEMA_VERSION`/`_NAME` against the
/// statement scan's own maximum.
///
/// Catches: a scan that stops early; and -- the #511 regression itself --
/// anyone replacing the derivation with a hand-written literal, which reds here
/// the moment the file moves past it. It does NOT by itself catch "keep the last
/// row instead of the maximum", because today's last row happens to be the
/// maximum; `the_head_is_the_maximum_row_whatever_order_the_ledger_is_written_in`
/// is the test that pins that.
#[test]
fn the_head_constants_are_the_highest_migration_in_the_init_sql() {
    let rows = ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL);
    let (version, name) = rows
        .iter()
        .max_by_key(|(version, _)| *version)
        .expect("sql/001_init_postgres.sql must record migrations");
    assert_eq!(
        POSTGRES_SCHEMA_VERSION, *version,
        "POSTGRES_SCHEMA_VERSION must be the highest migration in sql/001_init_postgres.sql"
    );
    assert_eq!(
        POSTGRES_SCHEMA_NAME, name,
        "POSTGRES_SCHEMA_NAME must name the highest migration in sql/001_init_postgres.sql"
    );
    // The head must also be findable in the file exactly as the constants spell
    // it, so a runtime ledger comparison against them can ever succeed. The
    // TUPLE is what is searched for, not `VALUES (<tuple>`: the head is allowed
    // to be the second tuple of a multi-row clause, a shape
    // `every_tuple_of_a_multi_row_values_clause_is_read` certifies.
    let tuple = format!("({POSTGRES_SCHEMA_VERSION}, '{POSTGRES_SCHEMA_NAME}')");
    assert!(
        POSTGRES_SCHEMA_SQL.contains(&tuple),
        "the derived head {POSTGRES_SCHEMA_VERSION}:{POSTGRES_SCHEMA_NAME} is not spelled in \
         sql/001_init_postgres.sql as {tuple}, so no live ledger row can ever match it"
    );
}

/// Every ledger ROW and every ledger STATEMENT in the file must be one the const
/// parser saw.
///
/// Pins `schema_migrations.rs`'s `rows`/`statements` counters (`rows += 1` after
/// each tuple, `statements += 1` after the table reference resolves) against two
/// independent readings.
///
/// Catches: a future migration written in a shape the const parser walks past --
/// a reformatted or qualified INSERT (statement count diverges) or a second
/// tuple on one `VALUES` clause (row count diverges). The old version of this
/// test compared statement counts only, which is precisely why the multi-row
/// blind spot stayed green. It does NOT catch a ledger row written by `COPY`,
/// `UPDATE`, `MERGE` or runtime-assembled SQL: all three readers anchor on
/// `INSERT` and go quiet on those together.
#[test]
fn every_ledger_row_and_statement_in_the_sql_is_seen_by_the_head_parser() {
    let statements = ledger_insert_statements(POSTGRES_SCHEMA_SQL);
    assert!(
        statements > 0,
        "sql/001_init_postgres.sql must contain ledger INSERT statements for this cross-check \
         to compare anything"
    );
    assert_eq!(
        POSTGRES_SCHEMA_LEDGER_STATEMENTS, statements,
        "the const parser must recognize every storage_schema_migrations INSERT in the file"
    );
    assert_eq!(
        POSTGRES_SCHEMA_LEDGER_ROWS,
        ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL).len(),
        "the const parser must read every row of every ledger VALUES clause"
    );
    assert!(
        POSTGRES_SCHEMA_LEDGER_ROWS >= statements,
        "each ledger statement contributes at least one row"
    );
}

/// Migration numbers must run 1..=head with no gaps.
///
/// Pins the derived head against the set of versions the statement scan reads.
///
/// Catches: a new migration numbered past the head (`061` while `060` is
/// missing), a deleted migration, and a head that is somehow larger than the
/// versions actually present -- i.e. the ways "highest number wins" could pick a
/// number the schema never applies.
#[test]
fn ledger_versions_run_contiguously_from_one_to_the_head() {
    let versions: BTreeSet<u64> = ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL)
        .into_iter()
        .map(|(version, _)| version)
        .collect();
    let expected: BTreeSet<u64> = (1..=POSTGRES_SCHEMA_VERSION).collect();
    let missing: Vec<u64> = expected.difference(&versions).copied().collect();
    assert!(
        missing.is_empty(),
        "sql/001_init_postgres.sql skips migration versions {missing:?}; the head \
         {POSTGRES_SCHEMA_VERSION} would then be applied on top of a gap"
    );
    assert_eq!(
        versions.iter().next_back().copied(),
        Some(POSTGRES_SCHEMA_VERSION),
        "no migration may be numbered above the derived head"
    );
}

/// A ledger row's name must encode its own version.
///
/// Pins every `(version, name)` pair the statement scan reads out of the file.
///
/// Catches: the copy-paste `VALUES (60, '059_...')`, where the version moves and
/// the name does not. The runtime validator looks up the head BY VERSION and
/// then compares the NAME, so a mismatched pair makes a correctly migrated
/// database report a missing migration forever. The nonzero floor is what stops
/// a broken reader from passing this vacuously (#500).
#[test]
fn every_ledger_name_encodes_its_own_version() {
    let rows = ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL);
    assert!(
        !rows.is_empty(),
        "the reader must find ledger rows to check"
    );
    for (version, name) in rows {
        assert!(
            name.starts_with(&format!("{version:03}_")),
            "migration {version} is named {name}; the name must start with its own \
             zero-padded version"
        );
    }
}

/// One version must not be recorded under two different names.
///
/// Pins the file, not the parser.
///
/// Catches: a duplicated ledger statement (the file legitimately records a few
/// versions twice, once inside a `DO` block and once bare) that was edited on
/// only one of its two sites -- which would make the head's identity depend on
/// which copy a reader happened to find.
#[test]
fn a_repeated_ledger_version_always_carries_the_same_name() {
    let rows = ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL);
    assert!(
        !rows.is_empty(),
        "the reader must find ledger rows to check"
    );
    for (version, name) in &rows {
        for (other_version, other_name) in &rows {
            if version == other_version {
                assert_eq!(
                    name, other_name,
                    "migration {version} is recorded under two different names"
                );
            }
        }
    }
}

/// The schema evidence the Admin API publishes is the derived head, not a
/// separately maintained value.
///
/// Pins `lib.rs:577-578` (`StorageSchemaEvidence::postgres_expected`).
///
/// Catches: reintroducing a literal in `StorageSchemaEvidence::postgres_expected`
/// (which the E2E harness compares byte-for-byte against `/admin/v1/status`).
#[test]
fn published_schema_evidence_reports_the_derived_head() {
    let evidence = crate::StorageSchemaEvidence::postgres_expected();
    assert_eq!(evidence.version, POSTGRES_SCHEMA_VERSION);
    assert_eq!(evidence.name, POSTGRES_SCHEMA_NAME);
    assert_eq!(evidence.engine, "postgres");
    assert!(evidence.validated);
}

// ---------------------------------------------------------------------------
// Fixtures.
//
// Everything above reads `sql/001_init_postgres.sql`, a file that parses today,
// so every shape it does not currently contain was unpinned -- the #500 shape.
// `head_migration` is a `const fn` over `&'static str`, so the tests below call
// it at RUNTIME with literal ledgers and assert on shapes the real file has
// never had.
// ---------------------------------------------------------------------------

/// The head is the MAXIMUM row, not the first one and not the last one.
///
/// Pins `schema_migrations.rs`'s `if entry_version > version` guard.
///
/// Catches: replacing that comparison with an unconditional assignment
/// (last-wins) -- the descending fixture then reports 59; and inverting it to
/// `<` or keeping only the first match (first-wins) -- the ascending fixture
/// then reports 59. Neither mutation is caught by the real-file tests, because
/// the real file's last row IS its maximum (`sql/001_init_postgres.sql:2666`).
/// Out-of-order rows are the realistic future edit: the file already re-records
/// versions 30, 31, 32, 38 and 51.
#[test]
fn the_head_is_the_maximum_row_whatever_order_the_ledger_is_written_in() {
    let descending = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_written_first')\n\
         ON CONFLICT (version) DO NOTHING;\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (59, '059_written_last')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(descending.version, 60, "last-wins would report 59 here");
    assert_eq!(descending.name, "060_written_first");

    let ascending = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (59, '059_written_first')\n\
         ON CONFLICT (version) DO NOTHING;\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_written_last')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(ascending.version, 60, "first-wins would report 59 here");
    assert_eq!(ascending.name, "060_written_last");
    assert_eq!(ascending.rows, 2);
    assert_eq!(ascending.statements, 2);
}

/// Every tuple of a multi-row `VALUES` clause is read.
///
/// Pins `schema_migrations.rs`'s tuple `loop` and its trailing
/// `if next < bytes.len() && bytes[next] == b','` continuation.
///
/// Catches: reading only the first tuple per statement -- the shape review
/// demonstrated, where the const head reports 59, the database built from the
/// same SQL reports 60, and `supabase-restart` bails on bookkeeping instead of
/// durability. That is #511 verbatim. Note the row/statement split: a
/// first-tuple-only parser still reports one statement, which is why
/// `every_ledger_row_and_statement_in_the_sql_is_seen_by_the_head_parser` now
/// compares rows too.
#[test]
fn every_tuple_of_a_multi_row_values_clause_is_read() {
    let sql = "INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (59, '059_first_tuple'), (60, '060_second_tuple')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(
        head.version, 60,
        "a first-tuple-only parser reports 59 here"
    );
    assert_eq!(head.name, "060_second_tuple");
    assert_eq!(head.rows, 2, "both tuples are rows");
    assert_eq!(head.statements, 1, "written as one statement");
    // The test-side readers must agree, or the cross-check above is vacuous --
    // and they read the SAME fixture string, so editing it cannot make them
    // compare different text.
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 2);
    assert_eq!(ledger_insert_statements(sql), 1);
}

/// A schema-qualified or double-quoted ledger INSERT is still the ledger.
///
/// Pins `schema_migrations.rs`'s table-reference resolution (`read_identifier`
/// plus the `bytes[qualifier] == b'.'` branch) and `identifier_is`.
///
/// Catches: going back to a single fixed
/// `"INSERT INTO storage_schema_migrations (version, name)"` anchor. Under that
/// anchor a qualified INSERT is walked past in total silence -- it also escapes
/// the old marker count -- so the head lags with no signal at all.
#[test]
fn a_schema_qualified_or_quoted_ledger_insert_is_not_walked_past() {
    let qualified = "INSERT INTO ferrogate_control.storage_schema_migrations (version, name)\n\
                     VALUES (60, '060_qualified')\n\
                     ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(qualified);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_qualified");
    assert_eq!(head.statements, 1);

    let quoted = head_migration(
        "INSERT INTO \"storage_schema_migrations\" (version, name)\n\
         VALUES (60, '060_quoted')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(quoted.version, 60);
    assert_eq!(quoted.name, "060_quoted");

    // ...and the qualified shape is visible to the two test-side readers, so the
    // count cross-check would not go quiet if the file ever adopted it.
    assert_eq!(ledger_insert_statements(qualified), 1);
    assert_eq!(ledger_rows_by_statement_scan(qualified).len(), 1);
}

/// The anchor is a SQL token sequence, not an 11-byte literal.
///
/// Pins `ledger_insert_at`: `keyword_at` (case-insensitive, whole word) for
/// `INSERT`/`INTO`/`ONLY`, the two `skip_ignorable` calls that separate them,
/// the spaced `.` qualifier branch, and `identifier_is`'s case folding of an
/// UNQUOTED table name. Pins `expect_ledger_columns` and the `VALUES` keyword
/// for the same three properties.
///
/// Catches: the mutation review named -- replacing
/// `skip_ignorable(bytes, cursor + 6)` with `cursor + 6 + 1`, which makes the
/// parser one-space-only while every other fixture and the real file stay
/// green. It also catches reverting any of these to a byte-exact match. Each of
/// these statements is legal Postgres that writes the ledger, and under the
/// previous anchor every one of them was walked past in silence: head lags,
/// all tests green, `supabase-restart` bails on bookkeeping. That is #511's
/// exact mechanism.
#[test]
fn the_ledger_anchor_is_a_token_sequence_not_a_fixed_string() {
    let sql = "insert into storage_schema_migrations (version, name) values (57, '057_lower');\n\
               INSERT\n  INTO ONLY Storage_Schema_Migrations ( VERSION , Name )\n  \
               VALUES (60, '060_folded');\n\
               INSERT  INTO ferrogate_control . storage_schema_migrations (version,name)\n  \
               VALUES (58, '058_spaced');\n";
    let head = head_migration(sql);
    assert_eq!(
        head.version, 60,
        "a fixed-string anchor reads none of these"
    );
    assert_eq!(head.name, "060_folded");
    assert_eq!(head.rows, 3);
    assert_eq!(head.statements, 3);
    assert_eq!(ledger_insert_statements(sql), 3);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 3);
}

/// A DOUBLE-QUOTED table name is compared exactly, the way Postgres compares it.
///
/// Pins the `quoted` arm of `identifier_is` (fold only when unquoted).
///
/// Catches: folding a quoted identifier too, which would adopt rows from
/// `"Storage_Schema_Migrations"` -- a genuinely different table in Postgres --
/// and push the head above what the database ever applied. The live row keeps
/// the fixture from passing merely because nothing matched.
#[test]
fn a_double_quoted_table_name_is_case_sensitive_like_postgres() {
    let sql = "INSERT INTO \"Storage_Schema_Migrations\" (version, name)\n\
               VALUES (999, '999_a_different_table');\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_the_ledger')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60, "a folded quoted name would report 999");
    assert_eq!(head.name, "060_the_ledger");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// Inserts into other tables are not mistaken for the ledger.
///
/// Pins `identifier_is`'s whole-identifier comparison (an identifier is read to
/// its end and its LENGTH is checked, never prefix-matched), the
/// `cursor += 1; continue;` skip for a non-ledger table, and the
/// `is_identifier_byte(bytes[at - 1])` boundary in front of the anchor.
///
/// Catches: widening the anchor into a prefix match -- `storage_schema_migrations_archive`
/// would then be parsed as the ledger; dropping the table check entirely -- the
/// unrelated `INSERT INTO plans (...)` at `sql/001_init_postgres.sql:1225`
/// would then be a compile error; and dropping the leading word boundary, which
/// makes `PREINSERT INTO ...` a statement.
#[test]
fn inserts_into_other_tables_are_not_mistaken_for_the_ledger() {
    let sql = "INSERT INTO plans (id, name, slug)\n\
               VALUES ('free', 'Free', 'free');\n\
               INSERT INTO storage_schema_migrations_archive (version, name)\n\
               VALUES (999, '999_not_the_ledger');\n\
               PREINSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (998, '998_not_a_statement');\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_the_real_one')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_the_real_one");
    assert_eq!(head.rows, 1, "only the ledger table contributes rows");
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

// ---------------------------------------------------------------------------
// Comments and literals: the scan reads SQL, not bytes.
//
// Review found the parser blind to comments in the direction that INFLATES the
// head -- a ledger row parked inside `/* ... */` was read as applied, while the
// database built from the same file was one migration behind, so
// `validate_postgres_schema` rejected every correctly migrated deployment. That
// is strictly worse than #511 itself, which only broke the harness.
// ---------------------------------------------------------------------------

/// A ledger row parked inside a `/* ... */` block is not a migration.
///
/// Pins the `/*` arm of `skip_ignorable` (and the `depth` counter that makes it
/// nest, as Postgres nests).
///
/// Catches: deleting comment handling -- exactly the state review found. The
/// head then reads 60 while the database this SQL builds is at 59, and
/// `validate_postgres_schema` (`lib.rs:9333-9340`) compares for EXACT equality,
/// so every deployment is rejected at startup. All three readers are asserted,
/// because if only the const parser learned about comments the cross-check
/// would red falsely on the next parked migration.
#[test]
fn a_ledger_row_parked_in_a_block_comment_is_not_a_migration() {
    let sql = "INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (59, '059_applied')\n\
               ON CONFLICT (version) DO NOTHING;\n\
               /*\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_parked')\n\
               ON CONFLICT (version) DO NOTHING;\n\
               /* still parked, nested */\n\
               */\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 59, "a comment-blind scan reports 60 here");
    assert_eq!(head.name, "059_applied");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// The same row commented out line by line is also not a migration.
///
/// Pins the `--` arm of `skip_ignorable`.
///
/// Catches: dropping `--` handling. Before this rework that shape did not
/// inflate the head, it failed the BUILD with the misleading message "is not
/// followed by `VALUES`", because the anchor matched inside the comment text.
#[test]
fn a_ledger_row_commented_out_line_by_line_is_not_a_migration() {
    let sql = "INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (59, '059_applied')\n\
               ON CONFLICT (version) DO NOTHING;\n\
               -- INSERT INTO storage_schema_migrations (version, name)\n\
               -- VALUES (60, '060_parked')\n\
               -- ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 59);
    assert_eq!(head.name, "059_applied");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// `/*` inside a `--` comment does not open a block comment.
///
/// Pins the SINGLE left-to-right pass in `skip_ignorable` and in
/// `sql_code_only`: whichever comment starts first consumes what follows.
///
/// Catches: the ordinary way a comment stripper is written -- remove `/* ... */`
/// over the whole text, then remove `--` lines. `sql/001_init_postgres.sql:1205`
/// really is `-- Gates /v1/assets/* (issue #176/#177) ...` and the file contains
/// no `*/` at all, so that mutation opens a comment running to end-of-file and
/// swallows all 64 ledger rows. On the real file the `rows == 0` arm turns that
/// into a build failure; this fixture makes it a test failure, which is where a
/// bug should be found.
#[test]
fn a_block_comment_marker_inside_a_line_comment_opens_nothing() {
    let sql = "-- Gates /v1/assets/* (issue #176/#177) the same way mcp_enabled gates MCP\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_after_the_comment')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_after_the_comment");
    assert_eq!(head.rows, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// A comment marker inside a `'...'` literal opens nothing either.
///
/// Pins `skip_noncode`'s literal arm (including its `''` escape handling).
///
/// Catches: teaching the scan about comments without teaching it about string
/// literals. Everything here is on ONE line, so a scan that saw the `--` inside
/// the literal would skip the ledger statement that follows it and read no rows
/// at all; one that saw the `/*` would run to end-of-file. Both are the price
/// of comment handling if it is added carelessly.
#[test]
fn a_comment_marker_inside_a_string_literal_opens_nothing() {
    let sql = "INSERT INTO plans (id, note) VALUES ('a--b', 'gates /v1/assets/* it''s fine'); \
               INSERT INTO storage_schema_migrations (version, name) \
               VALUES (60, '060_after_the_literal') ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_after_the_literal");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// Comments may sit between ANY two tokens of a ledger statement.
///
/// Pins every `skip_ignorable` call site inside `ledger_insert_at`,
/// `expect_ledger_columns` and the tuple loop -- if any one of them went back to
/// whitespace-only, this statement would stop parsing.
///
/// Catches: a half-done comment fix that only skips comments BETWEEN statements.
/// Note the direction: with the anchor resolved, a comment the parser could not
/// skip is a const panic, so this one fails loud rather than silent -- the
/// fixture makes it a test failure instead of a broken build.
#[test]
fn comments_between_the_tokens_of_a_ledger_statement_are_skipped() {
    let sql = "INSERT -- which statement?\n\
               INTO /* which schema? */ ferrogate_control.storage_schema_migrations\n\
               (version, /* the migration name */ name)\n\
               VALUES -- rows follow\n\
               (59, '059_a'), /* and */ (60, '060_b')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_b");
    assert_eq!(head.rows, 2);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 2);
}

/// The test-side comment stripper drops comments and nothing else.
///
/// Pins `sql_code_only`, which both test-side readers depend on.
///
/// Catches: a stripper that also eats code (the readers would then under-count
/// and every cross-check above would red) or that eats the contents of a
/// literal (migration names live in literals). Without this, the shared helper
/// would be the one unpinned piece of the cross-check.
#[test]
fn the_test_side_comment_stripper_drops_only_comments() {
    assert_eq!(
        sql_code_only("a -- comment\nb /* block /* nested */ */ c 'lit -- /* kept'"),
        "a \nb  c 'lit -- /* kept'"
    );
}

// ---------------------------------------------------------------------------
// Quoting: one apostrophe outside `'...'` used to cost 42 ledger rows.
//
// Review drove the previous round's parser over the real file with one ordinary
// block spliced in:
//
//     COPY notes (body) FROM stdin;
//     don't
//     \.
//
// The apostrophe in `don't` re-paired every quote after it, so `INSERT INTO
// storage_schema_migrations` was read as string DATA. 64 rows became 38, no
// panic, and the test-side readers -- which knew exactly as much about quoting
// -- agreed. Two answers, both pinned below: every quoted spelling Postgres has
// is lexed, and a quoted region that HIDES a ledger INSERT is a build failure
// regardless of which construct desynced it.
// ---------------------------------------------------------------------------

/// An apostrophe outside a `'...'` literal cannot silently eat ledger rows.
///
/// Pins `schema_migrations.rs`'s `reject_hidden_ledger_insert`, called from
/// `skip_quoted` just before a region is skipped.
///
/// Catches: the exact regression review demonstrated, and every future one of
/// its shape. Delete that call and this fixture reports version 59 with ONE row
/// -- migrations 60 and 61 gone, no panic, nothing red -- which is #511 itself,
/// a head that lags the database, arrived at by the one route nothing else on
/// this path watches. (Verified by const evaluation: with the call deleted the
/// same text evaluates to `version 59, rows 1`.) The `COPY` payload is
/// deliberately a construct the lexer does NOT model, and the trailing comment
/// is deliberately apostrophe-bearing, so the desync closes cleanly at
/// end-of-file and the unterminated-region arm never fires: the backstop is
/// what is left to make an unmodelled construct loud instead of lossy.
#[test]
#[should_panic(expected = "hides a storage_schema_migrations INSERT")]
fn a_stray_apostrophe_that_swallows_a_ledger_insert_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (59, '059_applied');\n\
         COPY notes (body) FROM stdin;\n\
         don't\n\
         \\.\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_would_be_lost');\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (61, '061_would_also_be_lost');\n\
         -- the ledger doesn't end here\n",
    );
}

/// An apostrophe inside a `$tag$ ... $tag$` body is data, not a literal.
///
/// Pins `dollar_tag_at` / `dollar_body_end` and the `$` arm of `skip_noncode`.
///
/// Catches: dropping dollar-quote handling. `$q$don't$q$` then opens a literal
/// that runs to the next apostrophe in the file -- the opening quote of the
/// next migration name -- and every ledger statement after it is read as string
/// data. The real file has 17 `DO $$` blocks, so this is not a hypothetical
/// spelling.
#[test]
fn an_apostrophe_inside_a_dollar_quoted_body_does_not_open_a_literal() {
    let sql = "DO $$\n\
               BEGIN\n\
                 PERFORM $q$don't$q$;\n\
               END $$;\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_after_the_body');\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60, "a desynced scan reads no rows here");
    assert_eq!(head.name, "060_after_the_body");
    assert_eq!(head.rows, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// An apostrophe inside a `"..."` identifier is part of the name.
///
/// Pins the `b'"'` arm of `skip_noncode` (and its doubled-delimiter escape).
///
/// Catches: leaving quoted identifiers out of the lexer. `"it's"` is a legal
/// Postgres table name; without this arm its apostrophe opens a literal and the
/// ledger statement after it is swallowed, so the head drops to whatever came
/// before.
#[test]
fn an_apostrophe_inside_a_double_quoted_identifier_does_not_open_a_literal() {
    let sql = "CREATE TABLE \"it's\" (a INT);\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_after_the_identifier');\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_after_the_identifier");
    assert_eq!(head.rows, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// `E'a\''` is one literal, not two.
///
/// Pins the `E'`/`e'` arm of `skip_noncode` and `skip_quoted`'s `backslash`
/// branch.
///
/// Catches: treating `E'...'` as a plain literal. The `\'` is then read as the
/// close and the following `'` opens a new one, so everything up to the next
/// apostrophe -- the next migration name -- becomes string data.
#[test]
fn a_backslash_escaped_quote_in_an_e_string_does_not_end_it() {
    let sql = "SELECT E'a\\'';\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_after_the_e_string');\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_after_the_e_string");
    assert_eq!(head.rows, 1);
}

/// A ledger row written in a FUNCTION body was never applied.
///
/// Pins the `$` arm of `skip_noncode` skipping a body the outer loop did not
/// claim as a `DO` block.
///
/// Catches: counting a `CREATE FUNCTION ... AS $b$ ... $b$` body as code, which
/// is what the previous round did -- appended to the real file it read version
/// 99 with 66 rows, i.e. a head ABOVE the database, and
/// `validate_postgres_schema` compares for EXACT equality, so every correctly
/// migrated deployment is rejected at startup. `DO` runs at load; a function
/// body is text the server stores.
#[test]
fn a_ledger_insert_in_a_function_body_is_not_a_migration() {
    let sql = "CREATE FUNCTION seed() RETURNS void AS $b$\n\
                 INSERT INTO storage_schema_migrations (version, name)\n\
                 VALUES (99, '099_never_applied');\n\
               $b$ LANGUAGE sql;\n\
               INSERT INTO storage_schema_migrations (version, name)\n\
               VALUES (60, '060_actually_applied');\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60, "a body-blind scan reports 99 here");
    assert_eq!(head.name, "060_actually_applied");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// A ledger row written inside a `DO` block IS applied.
///
/// Pins `do_block_at` and the branch of `head_migration` that steps INTO the
/// body instead of skipping it.
///
/// Catches: skipping every dollar-quoted body indiscriminately -- the tempting
/// half of the fix above. Three of the real file's ledger statements
/// (`sql/001_init_postgres.sql:1481`, `:1603`, `:1618`) sit inside `DO $$`
/// blocks, so that mutation drops rows from the real file too; here it leaves
/// no rows at all and the `rows == 0` arm fires.
#[test]
fn a_ledger_insert_inside_a_do_block_is_still_a_migration() {
    let sql = "DO $$\n\
               BEGIN\n\
                 INSERT INTO storage_schema_migrations (version, name)\n\
                 VALUES (60, '060_in_a_do') ON CONFLICT (version) DO NOTHING;\n\
               END $$;\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_in_a_do");
    assert_eq!(head.rows, 1);
    assert_eq!(head.statements, 1);
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// A schema NAMED `only` is not the `ONLY` keyword.
///
/// Pins the reference-first `ONLY` handling in `ledger_insert_at` (consume the
/// keyword only when no `.` follows it).
///
/// Catches: the previous shape, which matched `ONLY` and then demanded
/// whitespace after it, so `INSERT INTO only.storage_schema_migrations` failed
/// the separation check and was walked past in total silence -- a ledger
/// statement contributing rows to the database and none to the head.
#[test]
fn a_schema_named_only_is_not_the_only_keyword() {
    let sql = "INSERT INTO only.storage_schema_migrations (version, name)\n\
               VALUES (60, '060_schema_named_only');\n";
    let head = head_migration(sql);
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_schema_named_only");
    assert_eq!(head.statements, 1);
    // ...and `ONLY` as the keyword still resolves to the same table.
    let keyword = head_migration(
        "INSERT INTO ONLY storage_schema_migrations (version, name)\n\
         VALUES (60, '060_only_keyword');\n",
    );
    assert_eq!(keyword.version, 60);
    assert_eq!(keyword.name, "060_only_keyword");
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// Pins the escaped-quote arm of the ledger NAME scan.
///
/// Catches: adopting the raw bytes of `'060_it''s'` as the head name. The live
/// ledger row holds `060_it's` and the constant would hold `060_it''s`, so the
/// exact-equality comparison in `validate_postgres_schema` could never succeed
/// -- a head that is wrong in a way no amount of migrating fixes. Before this
/// arm the same input panicked with `is not closed with ')'`, pointing at the
/// wrong token.
#[test]
#[should_panic(expected = "contains an escaped quote")]
fn a_ledger_name_with_an_escaped_quote_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_it''s');\n",
    );
}

/// Pins the unterminated-identifier arm of `read_identifier`.
///
/// Catches: returning quietly at end-of-file, which reads the rest of the file
/// as one table name -- the same fail-open class as an unterminated literal,
/// and the one arm of it review found still silent.
#[test]
#[should_panic(expected = "identifier is never closed")]
fn an_unterminated_double_quoted_identifier_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO \"storage_schema_migrations (version, name)\n\
         VALUES (60, '060_x');\n",
    );
}

/// Pins the unterminated-body arm of `dollar_body_end`.
///
/// Catches: skipping to end-of-file when a `$tag$` is never closed, which hides
/// every migration after it behind a "no ledger rows" message on a file that
/// plainly has 64.
#[test]
#[should_panic(expected = "body is never closed")]
fn an_unclosed_dollar_quoted_body_is_a_hard_failure() {
    let _ = head_migration(
        "CREATE FUNCTION f() RETURNS void AS $b$\n\
         INSERT INTO storage_schema_migrations (version, name) VALUES (60, '060_x');\n",
    );
}

/// Pins the nesting arm of `head_migration`'s `DO` branch.
///
/// Catches: quietly mis-scoping a nested `DO` block -- the scan tracks one
/// body, so the inner block's closing tag would end the outer one and the rest
/// of the outer body would be read at the wrong nesting level. The file has no
/// nested blocks; if one is ever added this stops the build rather than
/// changing the head by an amount nobody predicted.
#[test]
#[should_panic(expected = "nested inside another `DO` block")]
fn a_do_block_nested_in_a_do_block_is_a_hard_failure() {
    let _ = head_migration(
        "DO $$\n\
         BEGIN\n\
           DO $inner$ BEGIN NULL; END $inner$;\n\
         END $$;\n\
         INSERT INTO storage_schema_migrations (version, name) VALUES (60, '060_x');\n",
    );
}

/// The test-side stripper reads the same quoted regions the const parser does.
///
/// Pins `sql_code_only`'s `$`, `"` and `E'` arms and `ends_with_do_introducer`,
/// each of which the const parser has a counterpart for.
///
/// Catches: leaving this reader knowing only `'...'`, which is how it agreed
/// with the const parser's wrong answer instead of contradicting it. Each
/// assertion below reds on its own: drop the `$` arm and the function body's
/// text survives into the code; drop the `DO` branch and a real ledger
/// statement disappears from it; drop the `"` or `E'` arm and the apostrophe
/// inside re-pairs everything after it.
#[test]
fn the_test_side_stripper_reads_the_same_quoted_regions_the_const_parser_does() {
    // A function body is not code; a `DO` body is.
    assert_eq!(
        sql_code_only("CREATE FUNCTION f() AS $b$ SELECT 1; $b$;\nDO $$ SELECT 2; $$;\n"),
        "CREATE FUNCTION f() AS ;\nDO  SELECT 2; ;\n"
    );
    // ...and comments inside a `DO` body are still comments.
    assert_eq!(
        sql_code_only("DO $$ -- parked\nSELECT 3; $$;"),
        "DO  \nSELECT 3; ;"
    );
    // A quoted identifier and an E-string are copied through whole, so the
    // apostrophes inside them pair with nothing.
    assert_eq!(
        sql_code_only("SELECT \"it's\", E'a\\'' -- gone\n, 'b';"),
        "SELECT \"it's\", E'a\\'' \n, 'b';"
    );
    // `$1` is a parameter, not a dollar quote.
    assert_eq!(sql_code_only("SELECT $1 -- gone\n;"), "SELECT $1 \n;");
}

/// The test-side anchor scan does not read an `INSERT` inside a literal.
///
/// Pins `insert_anchors`'s `if bytes[at] == b'\''` block, the other shared
/// helper.
///
/// Catches: deleting that block. Both test-side readers would then count an
/// `INSERT` written inside a string literal, and the statement cross-check
/// would red on a file the const parser reads correctly -- a false red on the
/// path whose whole point is to stop the harness failing on bookkeeping.
#[test]
fn the_test_side_anchor_scan_ignores_an_insert_inside_a_literal() {
    let code = "SELECT 'INSERT INTO plans (id) VALUES (''x'')';\n\
                INSERT INTO plans (id) VALUES ('y');\n";
    assert_eq!(
        insert_anchors(code).len(),
        1,
        "only the statement is an anchor; the quoted copy is data"
    );
    assert_eq!(insert_anchors("'no anchors in here: INSERT'").len(), 0);
}

// The panic arms. Each one is a COMPILE error when it fires during const
// evaluation of the real file; driving `head_migration` at runtime is how they
// can be asserted at all. "Fails closed" was previously claimed only in prose.

/// Pins the `if rows == 0` arm at the end of `head_migration`.
///
/// Catches: replacing that panic with a zero/default head -- the single most
/// dangerous mutation on this path, since a head of `0:` would make every live
/// ledger comparison fail forever, which is #511's own symptom.
#[test]
#[should_panic(expected = "no storage_schema_migrations ledger rows were found")]
fn a_file_with_no_ledger_rows_is_a_hard_failure() {
    let _ = head_migration("-- a schema file that records no migrations at all\n");
}

/// Pins the `if version == 0` arm next to it.
///
/// Catches: the OTHER route to a zero head, which review found still open --
/// `version`/`name_start`/`name_len` start at 0 and are only replaced under
/// `entry_version > version`, so a ledger whose rows are all numbered 0 returned
/// head `0` with the empty name, no panic, and `rows == 1` so the arm above
/// never fired. Low realism, but the module claims there is no default-zero on
/// this path and that claim has to be true.
#[test]
#[should_panic(expected = "records no version above 0")]
fn a_ledger_of_only_version_zero_rows_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (0, '000_genesis');\n",
    );
}

/// Pins the `LEDGER_VERSION_COLUMN`/`LEDGER_NAME_COLUMN` checks in
/// `expect_ledger_columns`.
///
/// Catches: skipping (rather than failing on) a ledger INSERT that writes a
/// different column list, e.g. `(name, version)` -- which would reverse the pair
/// and silently lower the head.
#[test]
#[should_panic(expected = "does not use the column list")]
fn a_ledger_insert_with_a_different_column_list_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (name, version)\n\
         VALUES ('060_swapped', 60);\n",
    );
}

/// Pins the `VALUES` keyword check.
///
/// Catches: walking past a ledger statement whose body is not a `VALUES` clause
/// (`INSERT ... SELECT`), which contributes rows to the database that this
/// parser cannot see.
#[test]
#[should_panic(expected = "is not followed by")]
fn a_ledger_insert_without_a_values_clause_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         SELECT 60, '060_from_a_select';\n",
    );
}

/// Pins the `digits == 0` arm.
///
/// Catches: accepting a non-numeric version and defaulting it to 0.
#[test]
#[should_panic(expected = "has no version number")]
fn a_ledger_row_without_a_version_number_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (sixty, '060_words');\n",
    );
}

/// Pins the missing-separator arm, which now carries its OWN message.
///
/// Catches: accepting `VALUES (60 '060_x')`. Review found this arm unreachable
/// from any fixture and indistinguishable from the missing-quote arm below,
/// because both emitted the same string -- deleting it left every test green.
#[test]
#[should_panic(expected = "has no `,` between its version and its name")]
fn a_ledger_row_without_a_separator_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60 '060_no_comma');\n",
    );
}

/// Pins the missing-quote arm.
///
/// Catches: reading a version and then accepting whatever follows as a name.
#[test]
#[should_panic(expected = "has no quoted name")]
fn a_ledger_row_without_a_quoted_name_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, 060_unquoted);\n",
    );
}

/// Pins the `at >= bytes.len()` arm inside the name scan.
///
/// Catches: letting an unterminated name run to end-of-file and be adopted as
/// the head name -- the head would then be a multi-kilobyte string that no live
/// ledger can ever match.
#[test]
#[should_panic(expected = "is unterminated")]
fn an_unterminated_ledger_name_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_never_closed\n",
    );
}

/// Pins the `at == entry_name_start` arm.
///
/// Catches: adopting `''` as the head name, which reads as "validated" while
/// naming nothing.
#[test]
#[should_panic(expected = "is empty")]
fn an_empty_ledger_name_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '');\n",
    );
}

/// Pins the closing-paren check at the end of each tuple.
///
/// Catches: ending a tuple at the closing quote instead of at `)`, which is how
/// a third column (`VALUES (60, '060_x', now())`) would be read as a plain
/// two-column row and any following tuple lost.
#[test]
#[should_panic(expected = "is not closed with")]
fn a_ledger_tuple_that_is_not_closed_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_extra_column', now());\n",
    );
}

/// Pins the `bytes[at] != b'('` arm at the top of the tuple loop.
///
/// Catches: treating a trailing comma as end-of-clause, i.e. silently accepting
/// a `VALUES` list whose next tuple was deleted or is still being written.
#[test]
#[should_panic(expected = "VALUES clause has no")]
fn a_dangling_tuple_separator_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_trailing_comma'), ;\n",
    );
}

/// Pins the unterminated-block-comment arm of `skip_ignorable`.
///
/// Catches: skipping to end-of-file instead of failing. A `/*` someone forgot to
/// close hides every migration after it, and with the `rows == 0` arm as the
/// only backstop the failure would be a confusing "no ledger rows" on a file
/// that plainly has 64.
#[test]
#[should_panic(expected = "comment is never closed")]
fn an_unterminated_block_comment_is_a_hard_failure() {
    let _ = head_migration(
        "/* parking this for now\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_parked');\n",
    );
}

/// Pins the unterminated-region arm of `skip_quoted`.
///
/// Catches: skipping to end-of-file instead of failing, the same way -- a stray
/// apostrophe near the end of the file would otherwise silently hide every
/// ledger row after it.
#[test]
#[should_panic(expected = "quoted region is never closed")]
fn an_unterminated_string_literal_is_a_hard_failure() {
    let _ = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (59, '059_applied');\n\
         SELECT 'oops;\n",
    );
}
