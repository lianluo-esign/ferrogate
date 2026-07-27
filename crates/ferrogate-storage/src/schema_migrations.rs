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
//! react to: it is to delete the copy. `head_migration` parses the migration
//! ledger out of the SQL text during const evaluation, so the constants are a
//! projection of the file rather than a claim about it, and adding migration
//! `060_...` moves them with zero edits here. Formats the parser does not
//! understand are a COMPILE error (const panic), not a silent skip -- a new
//! migration therefore cannot land unnoticed in either direction.
//!
//! What the parser deliberately does NOT decide is whether the DATABASE is
//! allowed to be ahead of this file: callers compare a live ledger against this
//! head for EXACT equality (`crate::validate_postgres_schema`, and the
//! `supabase-restart` harness). See `schema_migrations_test.rs` for the
//! properties that hold this module up.

/// The control-plane schema every Postgres/Supabase deployment is initialized
/// from, and the only source of truth for which migrations exist.
pub(crate) const POSTGRES_SCHEMA_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");

/// Every applied-migration record in the SQL is written as this statement
/// followed by `VALUES (<version>, '<name>')`, whether it stands alone or is
/// nested in a `DO $$ ... $$` block. Parsing anchors on the INSERT rather than
/// on `VALUES (` alone because the file carries many unrelated inserts.
const LEDGER_INSERT: &[u8] = b"INSERT INTO storage_schema_migrations (version, name)";
const LEDGER_VALUES: &[u8] = b"VALUES (";
const LEDGER_NAME_SEPARATOR: &[u8] = b", '";

/// The highest-numbered migration recorded in [`POSTGRES_SCHEMA_SQL`], plus how
/// many ledger statements were parsed to find it (some versions appear twice --
/// once inside a `DO` block and once as a bare statement -- so the entry count
/// is NOT the head version).
struct LedgerHead {
    version: u64,
    name: &'static str,
    /// Only read by the tests below (`POSTGRES_SCHEMA_LEDGER_ENTRIES`), which
    /// is the point: it exists so a migration the parser silently walked past
    /// can be detected by counting.
    #[cfg_attr(not(test), allow(dead_code))]
    entries: usize,
}

const HEAD: LedgerHead = head_migration(POSTGRES_SCHEMA_SQL);

/// Current schema migration version, derived from the ledger in
/// `sql/001_init_postgres.sql`. Exported so every consumer -- the runtime
/// validator and the E2E harness alike -- asserts against the one authority
/// instead of its own copy.
pub const POSTGRES_SCHEMA_VERSION: u64 = HEAD.version;
/// Name of [`POSTGRES_SCHEMA_VERSION`]'s migration, derived the same way.
pub const POSTGRES_SCHEMA_NAME: &str = HEAD.name;
/// Number of migration-ledger INSERT statements the parser recognized. Tests
/// compare this against a plain count of the marker in the file: if a future
/// migration is written in a shape the parser walks past, the counts diverge.
#[cfg(test)]
pub(crate) const POSTGRES_SCHEMA_LEDGER_ENTRIES: usize = HEAD.entries;

const fn head_migration(sql: &'static str) -> LedgerHead {
    let bytes = sql.as_bytes();
    let mut cursor = 0usize;
    let mut version = 0u64;
    let mut name_start = 0usize;
    let mut name_len = 0usize;
    let mut entries = 0usize;
    while cursor < bytes.len() {
        if !matches_at(bytes, cursor, LEDGER_INSERT) {
            cursor += 1;
            continue;
        }
        let mut at = cursor + LEDGER_INSERT.len();
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        // Anything the parser cannot read is a build failure rather than a
        // silently skipped migration: a skipped one would move the head
        // backwards and quietly re-create the #511 drift.
        if !matches_at(bytes, at, LEDGER_VALUES) {
            panic!(
                "sql/001_init_postgres.sql: a storage_schema_migrations INSERT is not followed by \
                 `VALUES (<version>, '<name>')`; the schema head cannot be derived"
            );
        }
        at += LEDGER_VALUES.len();
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
        if !matches_at(bytes, at, LEDGER_NAME_SEPARATOR) {
            panic!("sql/001_init_postgres.sql: a migration ledger row has no quoted name");
        }
        at += LEDGER_NAME_SEPARATOR.len();
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
        entries += 1;
        if entry_version > version {
            version = entry_version;
            name_start = entry_name_start;
            name_len = at - entry_name_start;
        }
        cursor = at;
    }
    if entries == 0 {
        panic!("sql/001_init_postgres.sql: no storage_schema_migrations ledger rows were found");
    }
    LedgerHead {
        version,
        name: const_substring(sql, name_start, name_len),
        entries,
    }
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
