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
//! * **Quoting is read the way Postgres lexes it, and a quoted region may not
//!   HIDE a ledger statement.** Review found the previous round's literal
//!   skipping fail-OPEN: it recognized only the bare `'...'` spelling, so ONE
//!   stray apostrophe outside it -- in a `COPY ... FROM stdin` payload, in
//!   `$q$don't$q$`, in the identifier `"it's"`, in `E'a\''` -- shifted every
//!   later quote by one and dropped ledger rows in silence (64 rows became 38,
//!   or 22, with no panic). Two things answer that, and the second is the one
//!   that does not depend on guessing every construct:
//!   1. `E'...'` (backslash escapes), `U&'...'`, `"..."` (doubled delimiter) and
//!      `$tag$ ... $tag$` are each lexed as their own region, so an apostrophe
//!      inside one is data and cannot shift anything;
//!   2. before a `'...'` or `"..."` region is skipped, its INTERIOR is scanned
//!      for a ledger `INSERT`, and finding one is a const panic. Any desync,
//!      from any construct modelled or not, either swallows a ledger anchor
//!      (arm 2 fires) or truncates a ledger statement (the arms below fire).
//!      Losing a migration quietly is what this module exists to prevent, so
//!      the fallback is a build failure, not a lower head.
//! * **`$tag$ ... $tag$` is scanned only where Postgres EXECUTES it.** This
//!   file's 17 `DO $$ ... $$` blocks run while it loads and record real ledger
//!   rows, so the scan steps INSIDE them. Any other dollar-quoted body -- a
//!   `CREATE FUNCTION ... AS $b$ ... $b$` -- is a string the server stores, so
//!   a ledger `INSERT` written there is NOT applied and is skipped; counting it
//!   used to put the head one migration ABOVE the database. One `DO` level is
//!   tracked, so a `DO` block nested in a `DO` block is a const panic rather
//!   than a mis-scoped body.
//! * **What counts as a ledger statement.** `INSERT INTO [ONLY]
//!   [<schema> .] <table>` where the table reference resolves to
//!   `storage_schema_migrations`: keywords in ANY case, any run of whitespace
//!   or comments between tokens, the table bare or schema-qualified, unquoted
//!   (case-folded, as Postgres folds it) or double-quoted (compared exactly, as
//!   Postgres compares it), and the identifier is always read whole and
//!   compared whole, never prefix-matched. `ONLY` is the keyword only when no
//!   `.` follows it, so a schema NAMED `only` still resolves to the ledger.
//! * **Such a statement MUST carry the column list `(version, name)` and a
//!   `VALUES` clause** of one or more `(<version>, '<name>')` tuples. EVERY
//!   tuple is read, so the head is the maximum over ROWS, not over statements,
//!   and a name carrying an escaped quote (`'060_it''s'`) is a panic rather
//!   than a constant no live ledger row could equal.
//! * **Anything else about such a statement is a const panic**, i.e. a COMPILE
//!   error, never a silently skipped migration. Nothing on this path has a
//!   fallback value: there is no `unwrap_or` or `unwrap_or_default`, and the two
//!   ways a zero head could still be produced -- no rows at all, and a ledger
//!   whose only rows are version `0` -- are themselves panics.
//! * **The residue, stated without flattery.** A ledger row recorded by
//!   `UPDATE`, by `MERGE`, or by `COPY ... FROM stdin` with the version in the
//!   payload is outside what this scan sees, and NOTHING detects it. Every
//!   reader of this file (this one, the two in `schema_migrations_test.rs`, and
//!   the harness's in `tools/ferrogate-test/src/storage_test.rs`) anchors on
//!   `INSERT`, so on that dimension they go quiet together. That residue is
//!   disclosed, not covered. What is no longer part of it: an `INSERT`
//!   assembled from a string literal at runtime now fails the BUILD, because
//!   the interior of every skipped literal is checked for a ledger anchor.
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
    // While scanning the body of a `DO $tag$ ... $tag$` block, `body_end` is the
    // offset of its CLOSING tag and `resume` the offset just past it. Everything
    // the scan does is then bounded by `body_end`, so a run-away literal or
    // comment inside a body cannot reach across the block and eat the ledger
    // rows that follow it: it fails the build instead.
    let mut body_end = 0usize;
    let mut resume = 0usize;
    while cursor < bytes.len() {
        if body_end != 0 && cursor >= body_end {
            cursor = resume;
            body_end = 0;
            resume = 0;
            continue;
        }
        let limit = if body_end != 0 { body_end } else { bytes.len() };
        // Comments and every other non-code region (string literals in all their
        // spellings, quoted identifiers, unexecuted dollar-quoted bodies) are not
        // statements. Doing this FIRST, in the same left-to-right pass, is what
        // stops `-- .../v1/assets/*` (a real line of the schema file) from
        // opening a block comment that swallows every migration after it.
        let code = skip_noncode(bytes, cursor, limit);
        if code != cursor {
            cursor = code;
            continue;
        }
        // `DO $$ ... $$` is the one dollar-quoted body Postgres RUNS while
        // loading this file, so it is stepped into rather than skipped: three of
        // the file's ledger rows are written inside one.
        let (is_do, do_body, do_end, do_after) = do_block_at(bytes, cursor, limit);
        if is_do {
            if body_end != 0 {
                panic!(
                    "sql/001_init_postgres.sql: a `DO` block is nested inside another `DO` block; \
                     this scan reads one level and will not guess at the rest"
                );
            }
            body_end = do_end;
            resume = do_after;
            cursor = do_body;
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
            // `'060_it''s'` is ONE name containing an apostrophe. The constants
            // are compared against a live ledger row byte for byte, and the row
            // holds `060_it's` while these bytes hold `060_it''s`, so adopting
            // the raw slice would guarantee a mismatch. Migration names are
            // `<version>_<snake_case>`, so this is a build failure with its own
            // message rather than an unescaping routine nothing would exercise.
            if at + 1 < bytes.len() && bytes[at + 1] == b'\'' {
                panic!(
                    "sql/001_init_postgres.sql: a migration ledger name contains an escaped quote \
                     (`''`); migration names must be plain `<version>_<snake_case>` identifiers"
                );
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
    // `INSERT INTO ONLY t` is the same table as `INSERT INTO t` -- but a SCHEMA
    // named `only` is not the keyword, so the reference is read first and `ONLY`
    // is consumed only when no `.` follows it. Requiring whitespace after the
    // keyword instead (the previous shape) walked past
    // `INSERT INTO only.storage_schema_migrations` without a sound.
    let (mut start, mut end, mut after, mut quoted) = read_identifier(bytes, cursor);
    if !quoted && identifier_is(bytes, start, end, false, b"only") {
        let dotted = skip_ignorable(bytes, after);
        if dotted >= bytes.len() || bytes[dotted] != b'.' {
            let (next_start, next_end, next_after, next_quoted) = read_identifier(bytes, dotted);
            start = next_start;
            end = next_end;
            after = next_after;
            quoted = next_quoted;
        }
    }
    // Keep only the last component of the reference, so
    // `ferrogate_control . storage_schema_migrations` and
    // `"storage_schema_migrations"` both resolve to the ledger, and
    // `storage_schema_migrations_archive` does not.
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
    skip_ignorable_to(bytes, from, bytes.len())
}

/// [`skip_ignorable`], stopping at `limit` -- the end of the `DO` body currently
/// being scanned, or the end of the file.
const fn skip_ignorable_to(bytes: &[u8], from: usize, limit: usize) -> usize {
    let mut at = from;
    loop {
        if at < limit && bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if at + 2 <= limit && matches_at(bytes, at, b"--") {
            at += 2;
            while at < limit && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if at + 2 <= limit && matches_at(bytes, at, b"/*") {
            // Postgres nests block comments, so depth is counted rather than
            // stopping at the first `*/`.
            let mut depth = 1usize;
            at += 2;
            while depth > 0 {
                if at >= limit {
                    panic!(
                        "sql/001_init_postgres.sql: a `/* ... */` comment is never closed; the \
                         rest of the file would be read as a comment"
                    );
                }
                if at + 2 <= limit && matches_at(bytes, at, b"/*") {
                    depth += 1;
                    at += 2;
                } else if at + 2 <= limit && matches_at(bytes, at, b"*/") {
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

/// [`skip_ignorable_to`], plus every region whose CONTENTS are not SQL code.
///
/// Only the OUTER scan uses this: between statements, a quoted region is data,
/// and a comment marker inside one (`'https://host/v1/*'`) must not open a
/// comment. Inside a ledger statement the name literal is read deliberately, so
/// the tuple parser uses [`skip_ignorable`] instead.
///
/// Every spelling Postgres gives a quoted region is recognized here, because
/// recognizing only ONE of them is worse than recognizing none: the previous
/// round skipped `'...'` alone, so a single apostrophe in a `COPY` payload, a
/// `$q$don't$q$` body or the identifier `"it's"` shifted every later quote by
/// one and dropped ledger rows without a word. See [`reject_hidden_ledger_insert`]
/// for the backstop that makes any surviving desync loud.
const fn skip_noncode(bytes: &[u8], from: usize, limit: usize) -> usize {
    let at = skip_ignorable_to(bytes, from, limit);
    if at >= limit {
        return at;
    }
    // `E'a\''` is one literal: inside it a backslash escapes the next byte, so a
    // reader that only knows `''` ends the literal one quote early.
    if (bytes[at] == b'E' || bytes[at] == b'e')
        && at + 1 < limit
        && bytes[at + 1] == b'\''
        && (at == 0 || !is_identifier_byte(bytes[at - 1]))
    {
        return skip_quoted(bytes, at + 1, limit, b'\'', true);
    }
    // `U&'...'` is a plain literal with a Unicode escape convention this scan
    // does not need to decode; what matters is where it ends.
    if (bytes[at] == b'U' || bytes[at] == b'u')
        && at + 2 < limit
        && bytes[at + 1] == b'&'
        && bytes[at + 2] == b'\''
        && (at == 0 || !is_identifier_byte(bytes[at - 1]))
    {
        return skip_quoted(bytes, at + 2, limit, b'\'', false);
    }
    if bytes[at] == b'\'' {
        return skip_quoted(bytes, at, limit, b'\'', false);
    }
    // A double-quoted IDENTIFIER is code, but its contents are not: `"it's"` is
    // a legal table name and its apostrophe is not a literal.
    if bytes[at] == b'"' {
        return skip_quoted(bytes, at, limit, b'"', false);
    }
    // A dollar-quoted body reached HERE is one the outer loop did not recognize
    // as a `DO` block, i.e. a function or procedure body: text the server
    // stores, not code it runs while loading this file.
    let (tagged, tag_len) = dollar_tag_at(bytes, at, limit);
    if tagged {
        return dollar_body_end(bytes, at, tag_len, limit) + tag_len;
    }
    at
}

/// Skip a `'...'` or `"..."` region opened at `open` and return the offset just
/// past its closing delimiter.
///
/// The doubled delimiter (`''`, `""`) is an escape rather than the end, and
/// `backslash` additionally makes `\x` an escape (the `E'...'` spelling). An
/// unterminated region is a const panic, never a skip to `limit`.
const fn skip_quoted(
    bytes: &[u8],
    open: usize,
    limit: usize,
    delimiter: u8,
    backslash: bool,
) -> usize {
    let mut scan = open + 1;
    loop {
        if scan >= limit {
            panic!(
                "sql/001_init_postgres.sql: a quoted region is never closed; the rest of the file \
                 would be read as its contents"
            );
        }
        if backslash && bytes[scan] == b'\\' {
            scan += 2;
            continue;
        }
        if bytes[scan] == delimiter {
            if scan + 1 < limit && bytes[scan + 1] == delimiter {
                scan += 2;
                continue;
            }
            reject_hidden_ledger_insert(bytes, open + 1, scan);
            return scan + 1;
        }
        scan += 1;
    }
}

/// A quoted region may not HIDE a ledger statement.
///
/// This is the backstop that does not depend on modelling every construct
/// correctly. Whatever makes the quote pairing desync -- an apostrophe in a
/// `COPY ... FROM stdin` payload, a spelling of a literal Postgres has and this
/// scan does not -- the observable effect is that a region swallows text it
/// should not have, and the text this module cannot afford to lose is a ledger
/// `INSERT`. Losing one silently lowers the head, which is issue #511 itself, so
/// finding one inside a skipped region is a build failure.
///
/// It also closes a residue the module used to only disclose: a ledger `INSERT`
/// assembled from a string literal and executed at runtime is now rejected
/// rather than counted as absent.
const fn reject_hidden_ledger_insert(bytes: &[u8], start: usize, end: usize) {
    let mut at = start;
    while at < end {
        let (is_ledger, _) = ledger_insert_at(bytes, at);
        if is_ledger {
            panic!(
                "sql/001_init_postgres.sql: a quoted region hides a storage_schema_migrations \
                 INSERT. Either an unbalanced quote made this scan read code as data -- which \
                 would drop migrations in silence -- or the ledger is written from a string at \
                 runtime, which no reader of this file can follow"
            );
        }
        at += 1;
    }
}

/// `$tag$` at `at`: returns `(matched, length of the whole delimiter)`.
///
/// `$$` and `$body$` are dollar-quote delimiters; `$1` is a positional
/// parameter and `$` on its own is neither.
const fn dollar_tag_at(bytes: &[u8], at: usize, limit: usize) -> (bool, usize) {
    if at >= limit || bytes[at] != b'$' {
        return (false, 0);
    }
    let mut scan = at + 1;
    if scan < limit && bytes[scan].is_ascii_digit() {
        return (false, 0);
    }
    while scan < limit && is_identifier_byte(bytes[scan]) {
        scan += 1;
    }
    if scan < limit && bytes[scan] == b'$' {
        (true, scan + 1 - at)
    } else {
        (false, 0)
    }
}

/// Offset of the delimiter that closes the dollar-quoted body opened at `open`.
const fn dollar_body_end(bytes: &[u8], open: usize, tag_len: usize, limit: usize) -> usize {
    let mut scan = open + tag_len;
    while scan + tag_len <= limit {
        let mut offset = 0usize;
        let mut same = true;
        while offset < tag_len {
            if bytes[scan + offset] != bytes[open + offset] {
                same = false;
                break;
            }
            offset += 1;
        }
        if same {
            return scan;
        }
        scan += 1;
    }
    panic!(
        "sql/001_init_postgres.sql: a `$...$` body is never closed; the rest of the file would be \
         read as its contents"
    )
}

/// `DO [LANGUAGE <ident>] $tag$ ... $tag$` -- the only dollar-quoted body this
/// file EXECUTES while loading.
///
/// Returns `(matched, body_start, body_end, after_body)`. The boundary in front
/// of the keyword is checked here, and `keyword_at` supplies the one behind it,
/// so `ON CONFLICT (version) DO NOTHING` is not a block.
const fn do_block_at(bytes: &[u8], at: usize, limit: usize) -> (bool, usize, usize, usize) {
    if at > 0 && is_identifier_byte(bytes[at - 1]) {
        return (false, 0, 0, 0);
    }
    if !keyword_at(bytes, at, b"do") {
        return (false, 0, 0, 0);
    }
    let mut cursor = skip_ignorable_to(bytes, at + 2, limit);
    if keyword_at(bytes, cursor, b"language") {
        let named = skip_ignorable_to(bytes, cursor + 8, limit);
        let (_, _, after, _) = read_identifier(bytes, named);
        cursor = skip_ignorable_to(bytes, after, limit);
    }
    let (tagged, tag_len) = dollar_tag_at(bytes, cursor, limit);
    if !tagged {
        return (false, 0, 0, 0);
    }
    let end = dollar_body_end(bytes, cursor, tag_len, limit);
    (true, cursor + tag_len, end, end + tag_len)
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
        if at >= bytes.len() {
            // Same fail-open class as an unterminated literal: returning here
            // would let the rest of the file be read as one table name.
            panic!(
                "sql/001_init_postgres.sql: a `\"...\"` identifier is never closed; the rest of \
                 the file would be read as its name"
            );
        }
        at += 1;
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
