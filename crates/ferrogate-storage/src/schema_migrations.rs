// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Derive the Postgres schema head (version + name) from the
// migration ledger in sql/001_init_postgres.sql at compile time (issue #511).

//! The schema head is READ OUT of the SQL, never copied next to it.
//!
//! `POSTGRES_SCHEMA_VERSION` / `POSTGRES_SCHEMA_NAME` used to be hand-written
//! literals sitting beside `include_str!("../../../sql/001_init_postgres.sql")`.
//! A hand-maintained copy of a value that lives somewhere else drifts, and this
//! one did: the constants stayed at `50:050_bucket_backed_asset_size_constraint`
//! while the SQL grew to 58, and because the E2E harness pinned a SECOND copy of
//! the same literal, `ferrogate-test supabase-restart` aborted on the stale pin
//! before it reached a single durability assertion (issue #511). A scenario that
//! always fails for an unrelated reason is indistinguishable from a scenario
//! that does not exist.
//!
//! The fix is not a fresher copy, and not a reminder test that a human must
//! react to: it is to delete the copy. [`head_migration`] parses the migration
//! ledger out of the SQL text during const evaluation, so the constants are a
//! projection of the file rather than a claim about it, and adding migration
//! `060_...` moves them with zero edits here.
//!
//! # What "fails closed" means here, exactly
//!
//! The first version of this module said a new migration "cannot land unnoticed
//! in either direction". That was too strong, and review found the two shapes
//! that walked past it: a second tuple on one `VALUES` clause, and a
//! schema-qualified table name. Both are parsed now, but the honest statement of
//! the guarantee is bounded by what a text scan can promise, so here it is:
//!
//! * A statement whose table reference resolves to `storage_schema_migrations`
//!   -- bare or schema-qualified, quoted or not -- MUST carry the column list
//!   `(version, name)` and a `VALUES` clause of one or more
//!   `(<version>, '<name>')` tuples. EVERY tuple is read, so the head is the
//!   maximum over rows, not over statements.
//! * Anything else about such a statement is a const panic, i.e. a COMPILE
//!   error, never a silently skipped migration. There is no `unwrap_or`,
//!   `unwrap_or_default` or default-zero anywhere on this path.
//! * A ledger row recorded by some OTHER statement -- `COPY`, `UPDATE`,
//!   `MERGE`, an `INSERT` assembled from a string at runtime -- is outside what
//!   this scan sees, and nothing here detects it. That residue is why
//!   `schema_migrations_test.rs` cross-checks the parser's row AND statement
//!   counts against a second reader written to a different shape, instead of
//!   resting on the promise above.
//!
//! What the parser deliberately does NOT decide is whether the DATABASE is
//! allowed to be ahead of this file: callers compare a live ledger against this
//! head for EXACT equality (`crate::validate_postgres_schema`, and the
//! `supabase-restart` harness). See `schema_migrations_test.rs` for the
//! properties that hold this module up -- including fixtures that drive
//! [`head_migration`] over ledgers this file does not contain, because a parser
//! only ever pointed at text that parses is untested against the text that does
//! not (#500).

/// The control-plane schema every Postgres/Supabase deployment is initialized
/// from, and the only source of truth for which migrations exist.
pub(crate) const POSTGRES_SCHEMA_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");

/// Applied-migration records are written as
/// `INSERT INTO [<schema>.]storage_schema_migrations (version, name) VALUES ...`,
/// whether the statement stands alone or is nested in a `DO $$ ... $$` block.
/// Parsing anchors on `INSERT INTO` and then resolves the table reference,
/// rather than on `VALUES (` alone, because the file carries unrelated inserts;
/// resolving the reference instead of matching one fixed 53-byte string is what
/// stops a qualified or quoted name from being walked past.
const LEDGER_INSERT_PREFIX: &[u8] = b"INSERT INTO";
const LEDGER_TABLE: &[u8] = b"storage_schema_migrations";
const LEDGER_COLUMNS: &[u8] = b"(version, name)";
const LEDGER_VALUES: &[u8] = b"VALUES";

/// The highest-numbered migration recorded in [`POSTGRES_SCHEMA_SQL`], plus the
/// two counts that let a test detect a row the parser walked past.
struct LedgerHead {
    version: u64,
    name: &'static str,
    /// How many `(<version>, '<name>')` tuples were read. Some versions appear
    /// twice -- once inside a `DO` block and once as a bare statement -- and one
    /// statement may carry several tuples, so this is NOT the head version and
    /// NOT the statement count.
    #[cfg_attr(not(test), allow(dead_code))]
    rows: usize,
    /// How many ledger INSERT statements were recognized. Read only by the tests
    /// below, which is the point: it is compared against an independent count
    /// over the raw text, so a statement shape the anchor stops matching shows
    /// up as a divergence instead of as a quietly lower head.
    #[cfg_attr(not(test), allow(dead_code))]
    statements: usize,
}

const HEAD: LedgerHead = head_migration(POSTGRES_SCHEMA_SQL);

/// Current schema migration version, derived from the ledger in
/// `sql/001_init_postgres.sql`. Exported so every consumer -- the runtime
/// validator and the E2E harness alike -- asserts against the one authority
/// instead of its own copy.
pub const POSTGRES_SCHEMA_VERSION: u64 = HEAD.version;
/// Name of [`POSTGRES_SCHEMA_VERSION`]'s migration, derived the same way.
pub const POSTGRES_SCHEMA_NAME: &str = HEAD.name;
/// Number of ledger ROWS the parser read out of the file.
#[cfg(test)]
pub(crate) const POSTGRES_SCHEMA_LEDGER_ROWS: usize = HEAD.rows;
/// Number of ledger INSERT STATEMENTS the parser recognized.
#[cfg(test)]
pub(crate) const POSTGRES_SCHEMA_LEDGER_STATEMENTS: usize = HEAD.statements;

/// Read the migration ledger out of `sql` and return its maximum row.
///
/// `const fn` over `&'static str`, so it is const-evaluated for
/// [`POSTGRES_SCHEMA_SQL`] (a malformed ledger is then a compile error) and
/// callable at runtime by the tests with literal fixtures.
const fn head_migration(sql: &'static str) -> LedgerHead {
    let bytes = sql.as_bytes();
    let mut cursor = 0usize;
    let mut version = 0u64;
    let mut name_start = 0usize;
    let mut name_len = 0usize;
    let mut rows = 0usize;
    let mut statements = 0usize;
    while cursor < bytes.len() {
        if !matches_at(bytes, cursor, LEDGER_INSERT_PREFIX) {
            cursor += 1;
            continue;
        }
        // `INSERT INTO [<schema>.]<table>`: read the reference and keep only its
        // last component, so `ferrogate_control.storage_schema_migrations` and
        // `"storage_schema_migrations"` both resolve to the ledger, and
        // `storage_schema_migrations_archive` does not (the identifier is read
        // whole and compared whole, never prefix-matched).
        let after_insert = skip_whitespace(bytes, cursor + LEDGER_INSERT_PREFIX.len());
        let (mut table_start, mut table_end, mut at) = read_identifier(bytes, after_insert);
        if at < bytes.len() && bytes[at] == b'.' {
            let (start, end, next) = read_identifier(bytes, at + 1);
            table_start = start;
            table_end = end;
            at = next;
        }
        if !region_eq(bytes, table_start, table_end, LEDGER_TABLE) {
            cursor += 1;
            continue;
        }
        // Past this point the statement IS a ledger write, so anything the
        // parser cannot read is a build failure rather than a silently skipped
        // migration: a skipped one would move the head backwards and quietly
        // re-create the #511 drift.
        statements += 1;
        at = skip_whitespace(bytes, at);
        if !matches_at(bytes, at, LEDGER_COLUMNS) {
            panic!(
                "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
                 column list `(version, name)`; the schema head cannot be derived"
            );
        }
        at = skip_whitespace(bytes, at + LEDGER_COLUMNS.len());
        if !matches_at(bytes, at, LEDGER_VALUES) {
            panic!(
                "sql/001_init_postgres.sql: a storage_schema_migrations INSERT is not followed by \
                 `VALUES (<version>, '<name>')`; the schema head cannot be derived"
            );
        }
        at += LEDGER_VALUES.len();
        // One `VALUES` clause may carry several tuples. Reading only the first
        // was the #511 shape all over again: `VALUES (59, '059_x'), (60, '060_y')`
        // silently reported 59 while the database built from the same file
        // reported 60.
        loop {
            at = skip_whitespace(bytes, at);
            if at >= bytes.len() || bytes[at] != b'(' {
                panic!(
                    "sql/001_init_postgres.sql: a storage_schema_migrations VALUES clause has no \
                     `(<version>, '<name>')` tuple"
                );
            }
            at = skip_whitespace(bytes, at + 1);
            let mut entry_version = 0u64;
            let mut digits = 0usize;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                entry_version = entry_version * 10 + (bytes[at] - b'0') as u64;
                at += 1;
                digits += 1;
            }
            if digits == 0 {
                panic!("sql/001_init_postgres.sql: a migration ledger row has no version number");
            }
            at = skip_whitespace(bytes, at);
            if at >= bytes.len() || bytes[at] != b',' {
                panic!("sql/001_init_postgres.sql: a migration ledger row has no quoted name");
            }
            at = skip_whitespace(bytes, at + 1);
            if at >= bytes.len() || bytes[at] != b'\'' {
                panic!("sql/001_init_postgres.sql: a migration ledger row has no quoted name");
            }
            at += 1;
            let entry_name_start = at;
            while at < bytes.len() && bytes[at] != b'\'' {
                at += 1;
            }
            if at >= bytes.len() {
                panic!("sql/001_init_postgres.sql: a migration ledger name is unterminated");
            }
            if at == entry_name_start {
                panic!("sql/001_init_postgres.sql: a migration ledger name is empty");
            }
            let entry_name_end = at;
            at = skip_whitespace(bytes, at + 1);
            if at >= bytes.len() || bytes[at] != b')' {
                panic!("sql/001_init_postgres.sql: a migration ledger row is not closed with `)`");
            }
            at += 1;
            rows += 1;
            // MAXIMUM, not last-seen and not first-seen: the file re-records
            // several versions and an out-of-order row is a realistic edit.
            if entry_version > version {
                version = entry_version;
                name_start = entry_name_start;
                name_len = entry_name_end - entry_name_start;
            }
            let next = skip_whitespace(bytes, at);
            if next < bytes.len() && bytes[next] == b',' {
                at = next + 1;
                continue;
            }
            break;
        }
        cursor = at;
    }
    if rows == 0 {
        panic!("sql/001_init_postgres.sql: no storage_schema_migrations ledger rows were found");
    }
    LedgerHead {
        version,
        name: const_substring(sql, name_start, name_len),
        rows,
        statements,
    }
}

const fn skip_whitespace(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// Read one SQL identifier, tolerating the double-quoted form, and return
/// `(start, end, after)` where `start..end` is the bare identifier text.
const fn read_identifier(bytes: &[u8], from: usize) -> (usize, usize, usize) {
    let mut at = from;
    let quoted = at < bytes.len() && bytes[at] == b'"';
    if quoted {
        at += 1;
    }
    let start = at;
    while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
        at += 1;
    }
    let end = at;
    if quoted && at < bytes.len() && bytes[at] == b'"' {
        at += 1;
    }
    (start, end, at)
}

const fn region_eq(bytes: &[u8], start: usize, end: usize, needle: &[u8]) -> bool {
    if end < start || end - start != needle.len() {
        return false;
    }
    matches_at(bytes, start, needle)
}

const fn matches_at(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    if at + needle.len() > bytes.len() {
        return false;
    }
    let mut offset = 0usize;
    while offset < needle.len() {
        if bytes[at + offset] != needle[offset] {
            return false;
        }
        offset += 1;
    }
    true
}

const fn const_substring(text: &'static str, start: usize, len: usize) -> &'static str {
    let (_, tail) = text.as_bytes().split_at(start);
    let (chunk, _) = tail.split_at(len);
    match core::str::from_utf8(chunk) {
        Ok(name) => name,
        Err(_) => panic!("sql/001_init_postgres.sql: migration name is not valid UTF-8"),
    }
}

#[cfg(test)]
#[path = "schema_migrations_test.rs"]
mod schema_migrations_test;
