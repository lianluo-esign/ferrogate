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
//! in either direction". That was too strong twice over: review found two
//! statement shapes that walked past the scan, and then found that the sentence
//! written to bound the guarantee was itself wider than the code. So here is
//! the guarantee, clause by clause, each one carrying a fixture in
//! `schema_migrations_test.rs`:
//!
//! * **The scan reads SQL, not lines or raw bytes.** `--` to end-of-line and
//!   nested `/* ... */` are comments wherever they appear -- between any two
//!   tokens of a ledger statement included -- and are skipped, because Postgres
//!   skips them: a ledger row parked inside a comment is a row the DATABASE
//!   does not have, and reading it would push the head ABOVE the database and
//!   reject every correctly migrated deployment. A `'...'` literal outside a
//!   recognized statement is data, not code, so no comment marker inside one
//!   starts a comment. An unterminated comment or literal is a const panic, not
//!   a silent skip to end-of-file.
//! * **What counts as a ledger statement.** `INSERT INTO [ONLY]
//!   [<schema> .] <table>` where the table reference resolves to
//!   `storage_schema_migrations`: keywords in ANY case, any run of whitespace
//!   or comments between tokens, the table bare or schema-qualified, unquoted
//!   (case-folded, as Postgres folds it) or double-quoted (compared exactly, as
//!   Postgres compares it), and the identifier is always read whole and
//!   compared whole, never prefix-matched.
//! * **Such a statement MUST carry the column list `(version, name)` and a
//!   `VALUES` clause** of one or more `(<version>, '<name>')` tuples. EVERY
//!   tuple is read, so the head is the maximum over ROWS, not over statements.
//! * **Anything else about such a statement is a const panic**, i.e. a COMPILE
//!   error, never a silently skipped migration. Nothing on this path has a
//!   fallback value: there is no `unwrap_or` or `unwrap_or_default`, and the two
//!   ways a zero head could still be produced -- no rows at all, and a ledger
//!   whose only rows are version `0` -- are themselves panics.
//! * **The residue, stated without flattery.** A ledger row recorded by any
//!   OTHER construct -- `COPY ... FROM stdin`, `UPDATE`, `MERGE`,
//!   `INSERT ... SELECT` off another table, an `INSERT` assembled from a string
//!   at runtime -- is outside what this scan sees, and NOTHING detects it. Every
//!   reader of this file (this one, the two in `schema_migrations_test.rs`, and
//!   the harness's in `tools/ferrogate-test/src/storage_test.rs`) anchors on
//!   `INSERT`, so on that dimension they go quiet together. That residue is
//!   disclosed, not covered.
//! * **What the cross-check actually covers** is a DIFFERENT residue: an
//!   `INSERT` shape this parser stops matching while a differently written
//!   reader still sees it. That is why `schema_migrations_test.rs` compares both
//!   the row count and the statement count against independent readings instead
//!   of resting on the promise above.
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

/// Table the applied-migration ledger is written to. Lower-case, because an
/// unquoted SQL identifier is folded before it is compared (a quoted one is
/// not); see [`identifier_is`].
const LEDGER_TABLE: &[u8] = b"storage_schema_migrations";
/// The two columns a ledger row must carry, in this order. `(name, version)`
/// would reverse the pair and silently lower the head, so it is a panic rather
/// than a skip.
const LEDGER_VERSION_COLUMN: &[u8] = b"version";
const LEDGER_NAME_COLUMN: &[u8] = b"name";

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
        // Comments and string literals are not statements. Doing this FIRST, in
        // the same left-to-right pass, is what stops `-- .../v1/assets/*` (a
        // real line of the schema file) from opening a block comment that
        // swallows every migration after it.
        let code = skip_noncode(bytes, cursor);
        if code != cursor {
            cursor = code;
            continue;
        }
        let (is_ledger, after_table) = ledger_insert_at(bytes, cursor);
        if !is_ledger {
            cursor += 1;
            continue;
        }
        // Past this point the statement IS a ledger write, so anything the
        // parser cannot read is a build failure rather than a silently skipped
        // migration: a skipped one would move the head backwards and quietly
        // re-create the #511 drift.
        statements += 1;
        let mut at = expect_ledger_columns(bytes, after_table);
        if !keyword_at(bytes, at, b"values") {
            panic!(
                "sql/001_init_postgres.sql: a storage_schema_migrations INSERT is not followed by \
                 `VALUES (<version>, '<name>')`; the schema head cannot be derived"
            );
        }
        at += 6;
        // One `VALUES` clause may carry several tuples. Reading only the first
        // was the #511 shape all over again: `VALUES (59, '059_x'), (60, '060_y')`
        // silently reported 59 while the database built from the same file
        // reported 60.
        loop {
            at = skip_ignorable(bytes, at);
            if at >= bytes.len() || bytes[at] != b'(' {
                panic!(
                    "sql/001_init_postgres.sql: a storage_schema_migrations VALUES clause has no \
                     `(<version>, '<name>')` tuple"
                );
            }
            at = skip_ignorable(bytes, at + 1);
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
            at = skip_ignorable(bytes, at);
            if at >= bytes.len() || bytes[at] != b',' {
                panic!(
                    "sql/001_init_postgres.sql: a migration ledger row has no `,` between its \
                     version and its name"
                );
            }
            at = skip_ignorable(bytes, at + 1);
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
            at = skip_ignorable(bytes, at + 1);
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
            let next = skip_ignorable(bytes, at);
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
    // The only remaining route to a zero head: every row the scan read is
    // numbered 0. Migrations are numbered from 1, and a head of `0:` makes every
    // live ledger comparison fail forever -- #511's own symptom -- so it is a
    // build failure rather than a value.
    if version == 0 {
        panic!(
            "sql/001_init_postgres.sql: the migration ledger records no version above 0; \
             migrations are numbered from 1"
        );
    }
    LedgerHead {
        version,
        name: const_substring(sql, name_start, name_len),
        rows,
        statements,
    }
}

/// `INSERT INTO [ONLY] [<schema> .] <table>` resolving to [`LEDGER_TABLE`].
///
/// Returns `(matched, offset_after_the_table_reference)`. Everything between
/// tokens goes through [`skip_ignorable`], so newlines, runs of spaces and
/// comments are all legal there; keywords are matched case-insensitively with
/// an identifier boundary on both sides, so `PREINSERT INTO ...` and
/// `INSERTINTO` are not statements.
const fn ledger_insert_at(bytes: &[u8], at: usize) -> (bool, usize) {
    if at > 0 && is_identifier_byte(bytes[at - 1]) {
        return (false, at);
    }
    if !keyword_at(bytes, at, b"insert") {
        return (false, at);
    }
    let mut cursor = at + 6;
    let separated = skip_ignorable(bytes, cursor);
    if separated == cursor {
        return (false, at);
    }
    cursor = separated;
    if !keyword_at(bytes, cursor, b"into") {
        return (false, at);
    }
    cursor += 4;
    let separated = skip_ignorable(bytes, cursor);
    if separated == cursor {
        return (false, at);
    }
    cursor = separated;
    // `INSERT INTO ONLY t` is the same table as `INSERT INTO t`.
    if keyword_at(bytes, cursor, b"only") {
        let separated = skip_ignorable(bytes, cursor + 4);
        if separated == cursor + 4 {
            return (false, at);
        }
        cursor = separated;
    }
    // Keep only the last component of the reference, so
    // `ferrogate_control . storage_schema_migrations` and
    // `"storage_schema_migrations"` both resolve to the ledger, and
    // `storage_schema_migrations_archive` does not.
    let (mut start, mut end, mut after, mut quoted) = read_identifier(bytes, cursor);
    let qualifier = skip_ignorable(bytes, after);
    if qualifier < bytes.len() && bytes[qualifier] == b'.' {
        let (next_start, next_end, next_after, next_quoted) =
            read_identifier(bytes, skip_ignorable(bytes, qualifier + 1));
        start = next_start;
        end = next_end;
        after = next_after;
        quoted = next_quoted;
    }
    if !identifier_is(bytes, start, end, quoted, LEDGER_TABLE) {
        return (false, at);
    }
    (true, after)
}

/// Consume `(version, name)` and return the offset just past it.
///
/// Parsed as identifiers rather than matched as one 15-byte literal, so
/// `( VERSION , name )` is the same column list -- and `(name, version)`, a
/// third column, or a missing one is still the same single panic.
const fn expect_ledger_columns(bytes: &[u8], from: usize) -> usize {
    let mut at = skip_ignorable(bytes, from);
    if at >= bytes.len() || bytes[at] != b'(' {
        panic!(
            "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
             column list `(version, name)`; the schema head cannot be derived"
        );
    }
    at = skip_ignorable(bytes, at + 1);
    let (start, end, after, quoted) = read_identifier(bytes, at);
    if !identifier_is(bytes, start, end, quoted, LEDGER_VERSION_COLUMN) {
        panic!(
            "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
             column list `(version, name)`; the schema head cannot be derived"
        );
    }
    at = skip_ignorable(bytes, after);
    if at >= bytes.len() || bytes[at] != b',' {
        panic!(
            "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
             column list `(version, name)`; the schema head cannot be derived"
        );
    }
    at = skip_ignorable(bytes, at + 1);
    let (start, end, after, quoted) = read_identifier(bytes, at);
    if !identifier_is(bytes, start, end, quoted, LEDGER_NAME_COLUMN) {
        panic!(
            "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
             column list `(version, name)`; the schema head cannot be derived"
        );
    }
    at = skip_ignorable(bytes, after);
    if at >= bytes.len() || bytes[at] != b')' {
        panic!(
            "sql/001_init_postgres.sql: a storage_schema_migrations INSERT does not use the \
             column list `(version, name)`; the schema head cannot be derived"
        );
    }
    skip_ignorable(bytes, at + 1)
}

/// Skip whitespace and comments -- the things that may appear between any two
/// tokens of a statement without changing it.
///
/// Comments are recognized in ONE left-to-right pass, never by hunting for a
/// marker across the whole text, which is not a style choice:
/// `sql/001_init_postgres.sql:1205` is `-- Gates /v1/assets/* ...` and the file
/// contains no `*/` at all, so anything that looked for block comments first
/// would open one that never closes and swallow every migration in the file.
const fn skip_ignorable(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    loop {
        if at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if matches_at(bytes, at, b"--") {
            at += 2;
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if matches_at(bytes, at, b"/*") {
            // Postgres nests block comments, so depth is counted rather than
            // stopping at the first `*/`.
            let mut depth = 1usize;
            at += 2;
            while depth > 0 {
                if at >= bytes.len() {
                    panic!(
                        "sql/001_init_postgres.sql: a `/* ... */` comment is never closed; the \
                         rest of the file would be read as a comment"
                    );
                }
                if matches_at(bytes, at, b"/*") {
                    depth += 1;
                    at += 2;
                } else if matches_at(bytes, at, b"*/") {
                    depth -= 1;
                    at += 2;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        return at;
    }
}

/// [`skip_ignorable`], plus a `'...'` literal.
///
/// Only the OUTER scan uses this: between statements, a string literal is data,
/// and a comment marker inside one (`'https://host/v1/*'`) must not open a
/// comment. Inside a ledger statement the name literal is read deliberately, so
/// the tuple parser uses [`skip_ignorable`] instead.
const fn skip_noncode(bytes: &[u8], from: usize) -> usize {
    let at = skip_ignorable(bytes, from);
    if at >= bytes.len() || bytes[at] != b'\'' {
        return at;
    }
    let mut scan = at + 1;
    loop {
        if scan >= bytes.len() {
            panic!(
                "sql/001_init_postgres.sql: a `'...'` literal is never closed; the rest of the \
                 file would be read as a string"
            );
        }
        if bytes[scan] == b'\'' {
            // `''` is an escaped quote, not the end of the literal.
            if matches_at(bytes, scan + 1, b"'") {
                scan += 2;
                continue;
            }
            return scan + 1;
        }
        scan += 1;
    }
}

/// Read one SQL identifier, tolerating the double-quoted form, and return
/// `(start, end, after, quoted)` where `start..end` is the bare identifier text.
const fn read_identifier(bytes: &[u8], from: usize) -> (usize, usize, usize, bool) {
    let mut at = from;
    if at < bytes.len() && bytes[at] == b'"' {
        at += 1;
        let start = at;
        while at < bytes.len() && bytes[at] != b'"' {
            at += 1;
        }
        let end = at;
        if at < bytes.len() {
            at += 1;
        }
        return (start, end, at, true);
    }
    let start = at;
    while at < bytes.len() && is_identifier_byte(bytes[at]) {
        at += 1;
    }
    (start, at, at, false)
}

/// Whole-identifier comparison against a lower-case `needle`.
///
/// An UNQUOTED identifier is folded before comparison, because Postgres folds
/// it: `Storage_Schema_Migrations` is the same table. A QUOTED one is compared
/// byte for byte, because Postgres does not fold it: `"Storage_Schema_Migrations"`
/// is a different table. The length is checked first either way, so nothing is
/// ever prefix-matched -- `storage_schema_migrations_archive` is not the ledger.
const fn identifier_is(
    bytes: &[u8],
    start: usize,
    end: usize,
    quoted: bool,
    needle: &[u8],
) -> bool {
    // `read_identifier` never returns `end < start`, so this cannot underflow.
    if end - start != needle.len() {
        return false;
    }
    let mut offset = 0usize;
    while offset < needle.len() {
        let byte = bytes[start + offset];
        let folded = if quoted { byte } else { ascii_lower(byte) };
        if folded != needle[offset] {
            return false;
        }
        offset += 1;
    }
    true
}

/// Case-insensitive keyword match with an identifier boundary after it, so
/// `INSERTED` is not `INSERT`. The boundary BEFORE the keyword is the caller's
/// job (only the anchor needs one).
const fn keyword_at(bytes: &[u8], at: usize, keyword: &[u8]) -> bool {
    if at + keyword.len() > bytes.len() {
        return false;
    }
    let mut offset = 0usize;
    while offset < keyword.len() {
        if ascii_lower(bytes[at + offset]) != keyword[offset] {
            return false;
        }
        offset += 1;
    }
    let end = at + keyword.len();
    end >= bytes.len() || !is_identifier_byte(bytes[end])
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + 32
    } else {
        byte
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
