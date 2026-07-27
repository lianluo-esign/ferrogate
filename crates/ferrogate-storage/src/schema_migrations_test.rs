// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Properties that hold the derived Postgres schema head honest --
// it must be the ACTUAL last migration in sql/001_init_postgres.sql (#511).

use super::{
    POSTGRES_SCHEMA_LEDGER_ENTRIES, POSTGRES_SCHEMA_NAME, POSTGRES_SCHEMA_SQL,
    POSTGRES_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

/// A SECOND, deliberately different reader of the same ledger. The constants are
/// produced by a byte-offset const-eval scan; this one is line-oriented and runs
/// at test time. Agreement between two independent readings is what makes these
/// tests capable of failing when the parser -- not just the file -- is wrong.
fn ledger_entries_by_line_scan(sql: &str) -> Vec<(u64, String)> {
    let mut entries = Vec::new();
    let mut lines = sql.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "INSERT INTO storage_schema_migrations (version, name)" {
            continue;
        }
        let values = lines
            .find(|candidate| !candidate.trim().is_empty())
            .expect("a migration ledger INSERT must be followed by its VALUES clause");
        let body = values
            .trim()
            .strip_prefix("VALUES (")
            .and_then(|rest| rest.split(')').next())
            .unwrap_or_else(|| panic!("unparsable migration ledger VALUES clause: {values}"));
        let (version, name) = body
            .split_once(", ")
            .unwrap_or_else(|| panic!("unparsable migration ledger VALUES clause: {values}"));
        let version: u64 = version
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("unparsable migration version: {values}"));
        entries.push((version, name.trim().trim_matches('\'').to_string()));
    }
    entries
}

/// The head constants must be the LAST migration the SQL actually contains.
///
/// Catches: the const parser keeping the first or an arbitrary entry instead of
/// the maximum; a scan that stops early; and -- the #511 regression itself --
/// anyone replacing the derivation with a hand-written literal, which reds here
/// the moment the file moves past it.
#[test]
fn the_head_constants_are_the_last_migration_in_the_init_sql() {
    let entries = ledger_entries_by_line_scan(POSTGRES_SCHEMA_SQL);
    let (version, name) = entries
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

/// Every ledger statement in the file must be one the const parser saw.
///
/// Catches: a future migration written in a shape the parser walks past (a
/// renamed/reformatted INSERT, an entry the anchor no longer matches). Without
/// this, such a migration would leave the head silently pointing at the previous
/// one -- exactly the failure mode #511 is about, just with a newer number.
#[test]
fn every_ledger_insert_in_the_sql_is_seen_by_the_head_parser() {
    let marker_occurrences = POSTGRES_SCHEMA_SQL
        .matches("INSERT INTO storage_schema_migrations")
        .count();
    assert_eq!(
        POSTGRES_SCHEMA_LEDGER_ENTRIES, marker_occurrences,
        "the const parser must recognize every storage_schema_migrations INSERT in the file"
    );
    assert_eq!(
        ledger_entries_by_line_scan(POSTGRES_SCHEMA_SQL).len(),
        marker_occurrences,
        "every storage_schema_migrations INSERT must carry a parsable VALUES clause"
    );
}

/// Migration numbers must run 1..=head with no gaps.
///
/// Catches: a new migration numbered past the head (`061` while `060` is
/// missing), a deleted migration, and a head that is somehow larger than the
/// versions actually present -- i.e. the ways "highest number wins" could pick a
/// number the schema never applies.
#[test]
fn ledger_versions_run_contiguously_from_one_to_the_head() {
    let versions: BTreeSet<u64> = ledger_entries_by_line_scan(POSTGRES_SCHEMA_SQL)
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
/// Catches: the copy-paste `VALUES (60, '059_...')`, where the version moves and
/// the name does not. The runtime validator looks up the head BY VERSION and
/// then compares the NAME, so a mismatched pair makes a correctly migrated
/// database report a missing migration forever.
#[test]
fn every_ledger_name_encodes_its_own_version() {
    for (version, name) in ledger_entries_by_line_scan(POSTGRES_SCHEMA_SQL) {
        assert!(
            name.starts_with(&format!("{version:03}_")),
            "migration {version} is named {name}; the name must start with its own \
             zero-padded version"
        );
    }
}

/// One version must not be recorded under two different names.
///
/// Catches: a duplicated ledger statement (the file legitimately records a few
/// versions twice, once inside a `DO` block and once bare) that was edited on
/// only one of its two sites -- which would make the head's identity depend on
/// which copy a reader happened to find.
#[test]
fn a_repeated_ledger_version_always_carries_the_same_name() {
    let entries = ledger_entries_by_line_scan(POSTGRES_SCHEMA_SQL);
    for (version, name) in &entries {
        for (other_version, other_name) in &entries {
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
