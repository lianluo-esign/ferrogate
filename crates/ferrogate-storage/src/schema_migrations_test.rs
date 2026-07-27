// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Properties that hold the derived Postgres schema head honest --
// it must be the ACTUAL last migration in sql/001_init_postgres.sql (#511).

use super::{
    head_migration, POSTGRES_SCHEMA_LEDGER_ROWS, POSTGRES_SCHEMA_LEDGER_STATEMENTS,
    POSTGRES_SCHEMA_NAME, POSTGRES_SCHEMA_SQL, POSTGRES_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

/// A SECOND, deliberately different reader of the same ledger. The constants are
/// produced by a byte-offset const-eval scan; this one splits the file into
/// statements at `;` and works with `str` pattern methods, at test time.
/// Agreement between two independent readings is what makes these tests capable
/// of failing when the parser -- not just the file -- is wrong.
///
/// It returns ROWS, not statements: one `VALUES` clause may carry several
/// tuples, and review found that counting statements is exactly how the const
/// parser's second-tuple blind spot stayed invisible.
fn ledger_rows_by_statement_scan(sql: &str) -> Vec<(u64, String)> {
    let mut rows = Vec::new();
    for statement in sql.split(';') {
        let Some((_, after_insert)) = statement.split_once("INSERT INTO") else {
            continue;
        };
        let Some((table_reference, after_table)) = after_insert.split_once('(') else {
            continue;
        };
        let table = table_reference
            .trim()
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .trim_matches('"');
        if table != "storage_schema_migrations" {
            continue;
        }
        let (columns, after_columns) = after_table
            .split_once(')')
            .unwrap_or_else(|| panic!("unterminated ledger column list: {statement}"));
        assert_eq!(
            columns.split_whitespace().collect::<Vec<_>>().join(" "),
            "version, name",
            "a ledger INSERT must write exactly (version, name): {statement}"
        );
        let mut rest = after_columns
            .trim_start()
            .strip_prefix("VALUES")
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

/// A THIRD, dumber reading: every `INSERT INTO` in the file whose table
/// reference ends in the ledger table, however it is qualified or quoted. It
/// knows nothing about `VALUES`, so it cannot be fooled by the same mistake the
/// other two readers might share.
fn ledger_insert_statements(sql: &str) -> usize {
    sql.match_indices("INSERT INTO")
        .filter(|(at, _)| {
            sql[*at..].split_once('(').is_some_and(|(reference, _)| {
                reference
                    .trim_end()
                    .trim_end_matches('"')
                    .ends_with("storage_schema_migrations")
            })
        })
        .count()
}

/// The head constants must be the LAST migration the SQL actually contains.
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
fn the_head_constants_are_the_last_migration_in_the_init_sql() {
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
    // it, so a runtime ledger comparison against them can ever succeed.
    assert!(POSTGRES_SCHEMA_SQL.contains(&format!(
        "VALUES ({POSTGRES_SCHEMA_VERSION}, '{POSTGRES_SCHEMA_NAME}')"
    )));
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
/// blind spot stayed green.
#[test]
fn every_ledger_row_and_statement_in_the_sql_is_seen_by_the_head_parser() {
    let statements = ledger_insert_statements(POSTGRES_SCHEMA_SQL);
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
/// database report a missing migration forever.
#[test]
fn every_ledger_name_encodes_its_own_version() {
    for (version, name) in ledger_rows_by_statement_scan(POSTGRES_SCHEMA_SQL) {
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
    let head = head_migration(
        "INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (59, '059_first_tuple'), (60, '060_second_tuple')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(
        head.version, 60,
        "a first-tuple-only parser reports 59 here"
    );
    assert_eq!(head.name, "060_second_tuple");
    assert_eq!(head.rows, 2, "both tuples are rows");
    assert_eq!(head.statements, 1, "written as one statement");
    // The test-side reader must agree, or the cross-check above is vacuous.
    assert_eq!(
        ledger_rows_by_statement_scan(
            "INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (59, '059_first_tuple'), (60, '060_second_tuple')\n\
             ON CONFLICT (version) DO NOTHING;\n"
        )
        .len(),
        2
    );
}

/// A schema-qualified or double-quoted ledger INSERT is still the ledger.
///
/// Pins `schema_migrations.rs`'s table-reference resolution (`read_identifier`
/// plus the `bytes[at] == b'.'` qualifier branch) and `region_eq`.
///
/// Catches: going back to a single fixed
/// `"INSERT INTO storage_schema_migrations (version, name)"` anchor. Under that
/// anchor a qualified INSERT is walked past in total silence -- it also escapes
/// the old marker count -- so the head lags with no signal at all.
#[test]
fn a_schema_qualified_or_quoted_ledger_insert_is_not_walked_past() {
    let qualified = head_migration(
        "INSERT INTO ferrogate_control.storage_schema_migrations (version, name)\n\
         VALUES (60, '060_qualified')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(qualified.version, 60);
    assert_eq!(qualified.name, "060_qualified");
    assert_eq!(qualified.statements, 1);

    let quoted = head_migration(
        "INSERT INTO \"storage_schema_migrations\" (version, name)\n\
         VALUES (60, '060_quoted')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(quoted.version, 60);
    assert_eq!(quoted.name, "060_quoted");

    // ...and both are visible to the two test-side readers, so the count
    // cross-check would not go quiet if the file ever adopted the shape.
    let sql = "INSERT INTO ferrogate_control.storage_schema_migrations (version, name)\n\
               VALUES (60, '060_qualified')\n\
               ON CONFLICT (version) DO NOTHING;\n";
    assert_eq!(ledger_insert_statements(sql), 1);
    assert_eq!(ledger_rows_by_statement_scan(sql).len(), 1);
}

/// Inserts into other tables are not mistaken for the ledger.
///
/// Pins `region_eq`'s whole-identifier comparison (an identifier is read to its
/// end and its LENGTH is checked, never prefix-matched) and the
/// `cursor += 1; continue;` skip for a non-ledger table.
///
/// Catches: widening the anchor into a prefix match -- `storage_schema_migrations_archive`
/// would then be parsed as the ledger; and dropping the table check entirely --
/// the unrelated `INSERT INTO plans (...)` at `sql/001_init_postgres.sql:1225`
/// would then be a compile error, so this failure would at least be loud, but
/// the fixture keeps it a test failure instead.
#[test]
fn inserts_into_other_tables_are_not_mistaken_for_the_ledger() {
    let head = head_migration(
        "INSERT INTO plans (id, name, slug)\n\
         VALUES ('free', 'Free', 'free');\n\
         INSERT INTO storage_schema_migrations_archive (version, name)\n\
         VALUES (999, '999_not_the_ledger');\n\
         INSERT INTO storage_schema_migrations (version, name)\n\
         VALUES (60, '060_the_real_one')\n\
         ON CONFLICT (version) DO NOTHING;\n",
    );
    assert_eq!(head.version, 60);
    assert_eq!(head.name, "060_the_real_one");
    assert_eq!(head.rows, 1, "only the ledger table contributes rows");
    assert_eq!(head.statements, 1);
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

/// Pins the `LEDGER_COLUMNS` check.
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

/// Pins the `LEDGER_VALUES` check.
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

/// Pins the two `has no quoted name` arms (missing separator, missing quote).
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
