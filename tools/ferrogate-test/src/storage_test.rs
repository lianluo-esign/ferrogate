// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for Supabase storage scenario isolation configuration.

use super::*;

fn supabase_storage(schema: &str, live: bool) -> ControlPlaneRestartStorage<'_> {
    ControlPlaneRestartStorage::Supabase {
        dsn: "postgresql://unused",
        tls: PostgresRestartTls {
            mode: "require",
            ca_cert_path: None,
        },
        schema,
        live,
    }
}

#[test]
fn restart_configs_preserve_one_schema_across_auto_and_validate_only() {
    let schema = "ferrogate_test_rst_fixture";
    let storage = supabase_storage(schema, true);
    let auto = storage.restart_config(
        "127.0.0.1:18080",
        false,
        false,
        StorageMigrationMode::Auto,
        None,
    );
    let validate = storage.restart_config(
        "127.0.0.1:18081",
        false,
        false,
        StorageMigrationMode::ValidateOnly,
        None,
    );

    for config in [&auto, &validate] {
        assert!(config.contains(&format!("postgres_schema: {schema}")));
        assert!(!config.contains("postgres_schema: ferrogate_control"));
    }
    assert!(auto.contains("migration_mode: auto"));
    assert!(validate.contains("migration_mode: validate_only"));
    assert_eq!(storage.readiness_timeout(), Duration::from_secs(180));
    assert_eq!(storage.request_timeout(), Duration::from_secs(300));
}

#[test]
fn token4ai_fixture_identity_is_threaded_into_config_auth_and_evidence() {
    let fixture = LiveToken4aiFixture::new("fixture-run");
    let config = supabase_storage("ferrogate_test_t4ai_fixture", true)
        .live_token4ai_provider_config(
            "127.0.0.1:18080",
            "https://api.token4ai.cloud/v1",
            "provider-model",
            &fixture,
            StorageMigrationMode::Auto,
        );

    assert!(config.contains(&format!("id: \"{}\"", fixture.client_id)));
    assert!(config.contains(&format!("key: \"{}\"", fixture.client_secret)));
    assert!(config.contains(&format!("organization_id: \"{}\"", fixture.tenant_id)));
    assert!(config.contains(&format!("project_id: \"{}\"", fixture.project_id)));
    assert!(!config.contains("\n  - id: client\n"));
    assert_eq!(
        fixture.authorization_header(),
        format!("Authorization: Bearer {}", fixture.client_secret)
    );

    let aggregate = serde_json::json!({
        "api_key_id": fixture.client_id,
        "logical_model": "live-chat",
        "provider": "token4ai"
    });
    let event = serde_json::json!({
        "tenant": {"api_key_id": fixture.client_id},
        "logical_model": "live-chat",
        "provider": "token4ai"
    });
    assert!(live_token4ai_evidence_matches(
        &aggregate,
        &fixture.client_id
    ));
    assert!(live_token4ai_evidence_matches(&event, &fixture.client_id));
    assert!(!live_token4ai_evidence_matches(&event, "client"));
}

#[test]
fn local_supabase_compatible_storage_keeps_short_readiness_timeout() {
    let storage = supabase_storage("ferrogate_control", false);
    assert_eq!(storage.readiness_timeout(), Duration::from_secs(60));
    assert_eq!(storage.request_timeout(), Duration::from_secs(60));
}

/// The schema the `supabase-restart` scenario applies, read here directly so
/// this test can disagree with the storage crate rather than echo it.
const CONTROL_PLANE_INIT_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");

/// Maximum `(version, name)` recorded by the migration ledger in `sql` -- the
/// answer the harness must be expecting, computed without consulting the
/// harness or `ferrogate_storage`.
///
/// This used to be a LINE-oriented reader: it required the whole-line anchor
/// `INSERT INTO storage_schema_migrations (version, name)` and read only the
/// first tuple of the following clause. `ferrogate-storage` widened its parser
/// to statements in the #511 rework, and review pointed out that this reader --
/// a fourth one, in another crate -- was left behind, so the first ledger row
/// written in a shape that rework legitimised would red the test below FALSELY.
/// Loud rather than silent, but "the scenario is blocked on its own
/// bookkeeping" is the exact ergonomics #511 exists to end.
fn head_of_ledger(sql: &str) -> (u64, String) {
    let mut head: Option<(u64, String)> = None;
    // Comments are not statements: a migration parked inside `/* ... */` is one
    // the database does not have, so reading it would put the harness ahead of
    // every deployment it tests.
    let code = strip_sql_comments(sql);
    let upper = code.to_ascii_uppercase();
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    for (at, _) in upper.match_indices("INSERT") {
        if at > 0 && word(code.as_bytes()[at - 1]) {
            continue;
        }
        let Some(after_into) = after_keyword(&code[at..], "INSERT")
            .and_then(|rest| after_keyword(rest.trim_start(), "INTO"))
        else {
            continue;
        };
        let after_only = after_keyword(after_into.trim_start(), "ONLY").unwrap_or(after_into);
        let Some((reference, after_table)) = after_only.trim_start().split_once('(') else {
            continue;
        };
        let table = reference
            .trim()
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .trim();
        if !resolves_to_ledger(table) {
            continue;
        }
        let mut clause = after_table
            .split_once(')')
            .and_then(|(_, rest)| {
                let rest = rest.trim_start();
                rest.get(.."VALUES".len())
                    .filter(|keyword| keyword.eq_ignore_ascii_case("VALUES"))
                    .map(|_| &rest["VALUES".len()..])
            })
            .unwrap_or_else(|| panic!("unparsable migration ledger statement at byte {at}"));
        // EVERY tuple, not just the first: `VALUES (59, '059_a'), (60, '060_b')`
        // records two migrations and the harness must expect the later one.
        loop {
            let (tuple, tail) = clause
                .trim_start()
                .strip_prefix('(')
                .and_then(|body| body.split_once(')'))
                .unwrap_or_else(|| panic!("unparsable migration ledger VALUES clause: {clause}"));
            let (version, name) = tuple
                .split_once(',')
                .unwrap_or_else(|| panic!("unparsable migration ledger tuple: {tuple}"));
            let version: u64 = version
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("unparsable migration version: {tuple}"));
            if head.as_ref().is_none_or(|(seen, _)| version > *seen) {
                head = Some((version, name.trim().trim_matches('\'').to_string()));
            }
            clause = tail.trim_start();
            match clause.strip_prefix(',') {
                Some(next_tuple) => clause = next_tuple,
                None => break,
            }
        }
    }
    head.expect("the control-plane SQL must record migrations")
}

/// True when a table reference's last dot-component IS the ledger table.
///
/// Postgres folds an UNQUOTED identifier and compares a QUOTED one byte for
/// byte, so `"Storage_Schema_Migrations"` is a DIFFERENT table. This reader used
/// to strip the quotes and fold anyway, which made it read a row
/// `ferrogate-storage` deliberately ignores and red
/// `the_supabase_restart_migration_expectation_is_the_head_of_the_applied_sql`
/// falsely -- the scenario blocked on its own bookkeeping again.
fn resolves_to_ledger(reference: &str) -> bool {
    let table = reference
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .trim();
    match table.strip_prefix('"').and_then(|q| q.strip_suffix('"')) {
        Some(quoted) => quoted == "storage_schema_migrations",
        None => table.eq_ignore_ascii_case("storage_schema_migrations"),
    }
}

/// Does a stored (non-`DO`) dollar-quoted body hold a ledger `INSERT`?
///
/// Anchored exactly the way [`head_of_ledger`] anchors, so there is no second
/// matcher to drift: whole-word `INSERT`, then `INTO`, then optional `ONLY`,
/// then the table reference.
fn body_hides_a_ledger_insert(body: &str) -> bool {
    let upper = body.to_ascii_uppercase();
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    upper.match_indices("INSERT").any(|(at, _)| {
        if at > 0 && word(body.as_bytes()[at - 1]) {
            return false;
        }
        let Some(after_into) = after_keyword(&body[at..], "INSERT")
            .and_then(|rest| after_keyword(rest.trim_start(), "INTO"))
        else {
            return false;
        };
        let after_only = after_keyword(after_into.trim_start(), "ONLY").unwrap_or(after_into);
        after_only
            .trim_start()
            .split_once('(')
            .is_some_and(|(reference, _)| resolves_to_ledger(reference))
    })
}

/// `keyword` at the front of `text`, case-insensitively and as a whole word;
/// returns what follows it.
fn after_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    if !text.get(..keyword.len())?.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &text[keyword.len()..];
    (!rest.starts_with(|char: char| char.is_ascii_alphanumeric() || char == '_')).then_some(rest)
}

/// Drop what Postgres would not EXECUTE while loading this file -- `--` to
/// end-of-line, nested `/* ... */`, and dollar-quoted bodies that are not `DO`
/// blocks -- keeping every quoted region verbatim (a migration name lives in
/// one). ONE left-to-right pass, earliest marker first:
/// `sql/001_init_postgres.sql:1205` reads `-- Gates /v1/assets/* ...` and the
/// file contains no `*/` at all, so stripping block comments in a pass of their
/// own would swallow the file.
///
/// Knowing only the `'...'` spelling is what let a single apostrophe elsewhere
/// -- in a `COPY` payload, in `$q$don't$q$`, in the identifier `"it's"` -- shift
/// every later quote and drop ledger rows; `ferrogate-storage` was found doing
/// exactly that, so this fourth reader learns the same lexing rather than
/// inheriting the same blind spot.
fn strip_sql_comments(sql: &str) -> String {
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
        let bytes = rest.as_bytes();
        match marker {
            "--" => rest = rest.find('\n').map_or("", |end| &rest[end..]),
            "/*" => {
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
                assert_eq!(depth, 0, "a `/* ... */` comment is never closed");
                // A block comment IS whitespace to Postgres, so it separates the
                // tokens around it. Without this separator `INSERT/*c*/INTO`
                // collapsed to `INSERTINTO` and this reader missed a statement
                // the database applies (#511).
                code.push(' ');
                rest = &rest[end..];
            }
            "$" => match dollar_tag(rest) {
                // `$1` is a positional parameter, not a quote.
                None => {
                    code.push('$');
                    rest = &rest[1..];
                }
                Some(tag) => {
                    let body = &rest[tag.len()..];
                    let end = body
                        .find(tag)
                        .unwrap_or_else(|| panic!("a `{tag} ... {tag}` body is never closed"));
                    // A `DO` body runs as the file loads and records real ledger
                    // rows. Any other body is a string -- and whether the server
                    // ever RUNS that string is not something this text decides:
                    // `CREATE PROCEDURE p() AS $b$ ... $b$;` applies nothing
                    // until `CALL p();` applies all of it. `ferrogate-storage`
                    // refuses such a body rather than guessing, so this reader
                    // refuses it too; four readers disagreeing about which rows
                    // exist is the failure this file exists to prevent.
                    if ends_with_do_introducer(&code) {
                        code.push_str(&strip_sql_comments(&body[..end]));
                    } else {
                        assert!(
                            !body_hides_a_ledger_insert(&body[..end]),
                            "a stored `{tag} ... {tag}` body hides a storage_schema_migrations \
                             INSERT; `CALL`, `SELECT f()` and `EXECUTE` all apply it"
                        );
                    }
                    rest = &body[end + tag.len()..];
                }
            },
            _ => {
                let delimiter = marker.as_bytes()[0];
                let escapes = delimiter == b'\'' && ends_with_e_prefix(&code);
                let mut scan = 1usize;
                let end = loop {
                    assert!(scan < bytes.len(), "a quoted region is never closed");
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

/// The `supabase-restart` migration assertion must expect the head of the SQL
/// the scenario actually applies.
///
/// Catches: the #511 regression in its original form -- a hand-written
/// `"50:050_bucket_backed_asset_size_constraint"` (or any other literal) in
/// place of the derived head. Because the expected value is recomputed here from
/// the SQL, ANY divergence between the harness's expectation and the file reds,
/// including the harness simply falling behind a new migration.
///
/// Does NOT catch: a ledger row written by `COPY`, `UPDATE` or `MERGE`. Like the
/// three readers in `ferrogate-storage`, this one anchors on `INSERT`, so on that
/// dimension they all go quiet together.
///
/// It does not skip `'...'` literals when hunting for the anchor -- review
/// checked this reader shape by shape and found no lag anywhere in it, which is
/// why `insert_anchors` in `ferrogate-storage` was rewritten to match rather
/// than the other way round. A literal containing the words
/// `INSERT INTO storage_schema_migrations` would be read here; it cannot reach
/// this assertion, because `region_hides_ledger_insert` makes that same text a
/// const panic and `ferrogate-storage` does not build at all.
#[test]
fn the_supabase_restart_migration_expectation_is_the_head_of_the_applied_sql() {
    let (version, name) = head_of_ledger(CONTROL_PLANE_INIT_SQL);
    assert_eq!(expected_head_migration(), format!("{version}:{name}"));
}

/// The harness's own reader must read the ledger shapes listed here the way
/// `ferrogate-storage` reads them.
///
/// It does not CALL the storage parser -- `head_migration` is private to that
/// crate -- so each expectation below is written out, and the name says
/// "listed here" rather than "every shape" for that reason.
///
/// Pins `head_of_ledger` and `strip_sql_comments` against the shapes the #511
/// rework settled on the storage side: a second tuple in one `VALUES` clause, a
/// schema-qualified table, keywords in any case with `ONLY`, a row parked
/// inside a comment, a case-sensitive double-quoted table name, an apostrophe
/// living outside a `'...'` literal, and a stored body carrying no ledger row.
/// The stored body that DOES carry one is
/// `the_harness_reader_refuses_a_ledger_row_inside_a_stored_body`, below.
///
/// Catches: leaving this reader line-oriented, which is where review found it;
/// and folding a quoted identifier, which review found here after the last
/// round. Under the old whole-line anchor plus `body.split(')').next()`, the
/// first ledger row written in any of these shapes made
/// `the_supabase_restart_migration_expectation_is_the_head_of_the_applied_sql`
/// red FALSELY -- the scenario blocked on its own bookkeeping again -- and a
/// parked row would have pushed the harness's expectation ABOVE the database.
#[test]
fn the_harness_ledger_reader_reads_the_ledger_shapes_listed_here() {
    assert_eq!(
        head_of_ledger(
            "INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (59, '059_first_tuple'), (60, '060_second_tuple');\n"
        ),
        (60, "060_second_tuple".to_string()),
        "a first-tuple-only reader reports 59 here"
    );
    assert_eq!(
        head_of_ledger(
            "insert into only ferrogate_control . storage_schema_migrations ( version , name )\n\
             values (60, '060_qualified');\n"
        ),
        (60, "060_qualified".to_string()),
        "a whole-line, case-exact anchor reads nothing here"
    );
    assert_eq!(
        head_of_ledger(
            "INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (59, '059_applied');\n\
             /*\n\
             INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (60, '060_parked');\n\
             */\n\
             -- INSERT INTO storage_schema_migrations (version, name)\n\
             -- VALUES (61, '061_also_parked');\n"
        ),
        (59, "059_applied".to_string()),
        "a comment-blind reader would put the harness one migration ahead of the database"
    );
    // Postgres does not fold a quoted identifier, so `"Storage_Schema_Migrations"`
    // is a different table -- the shape this reader used to fold and the storage
    // parser never did.
    assert_eq!(
        head_of_ledger(
            "INSERT INTO \"Storage_Schema_Migrations\" (version, name)\n\
             VALUES (999, '999_a_different_table');\n\
             INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (60, '060_the_ledger');\n"
        ),
        (60, "060_the_ledger".to_string()),
        "a reader that folds a quoted name reports 999 and reds the expectation falsely"
    );
    // An apostrophe outside a `'...'` literal must not re-pair the quotes that
    // follow it: `$q$don't$q$` and `"it's"` are both legal, and under the
    // previous stripper each swallowed the statement after it.
    assert_eq!(
        head_of_ledger(
            "DO $$ BEGIN PERFORM $q$don't$q$; END $$;\n\
             CREATE TABLE \"it's\" (a INT);\n\
             INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (60, '060_after_the_apostrophes');\n"
        ),
        (60, "060_after_the_apostrophes".to_string()),
        "a reader that knows only `'...'` reads nothing after the first stray apostrophe"
    );
    // A stored body with no ledger row in it is skipped, so a schema file that
    // ships helper functions still reads.
    assert_eq!(
        head_of_ledger(
            "CREATE FUNCTION touch() RETURNS void AS $b$\n\
               INSERT INTO audit_log (note) VALUES ('touched');\n\
             $b$ LANGUAGE sql;\n\
             INSERT INTO storage_schema_migrations (version, name)\n\
             VALUES (60, '060_actually_applied');\n"
        ),
        (60, "060_actually_applied".to_string()),
        "a body-blind reader reports the audit row and cannot parse its VALUES"
    );
}

/// A ledger row inside a STORED dollar-quoted body is refused here too.
///
/// Pins `strip_sql_comments`' `else` branch and `body_hides_a_ledger_insert`.
///
/// Catches: this reader keeping the round-3 rule (skip every non-`DO` body)
/// after `ferrogate-storage` stopped guessing. `CREATE PROCEDURE p() AS $b$
/// INSERT ... $b$; CALL p();` writes a row the DATABASE has, so a reader that
/// skips it reports a head BELOW the database and the restart scenario fails on
/// bookkeeping -- #511's own mechanism -- while the storage crate refuses to
/// build. Whichever answer is right, the two must not differ.
#[test]
#[should_panic(expected = "body hides a storage_schema_migrations INSERT")]
fn the_harness_reader_refuses_a_ledger_row_inside_a_stored_body() {
    let _ = head_of_ledger(
        "CREATE PROCEDURE p() AS $b$\n\
           INSERT INTO storage_schema_migrations (version, name)\n\
           VALUES (60, '060_via_call');\n\
         $b$ LANGUAGE sql;\n\
         CALL p();\n",
    );
}

/// A block comment ADJACENT to a token still separates it for this reader too.
///
/// `the_harness_ledger_reader_reads_the_ledger_shapes_listed_here` spaces its
/// comments out, so it stayed green while `strip_sql_comments` was deleting
/// `/* ... */` and closing the gap -- turning `INSERT/*c*/INTO` into
/// `INSERTINTO`, which the `"INSERT"` anchor never matches. The harness would
/// then read a LOWER head than the database actually has and the scenario would
/// fail pointing at the wrong thing (#511).
///
/// Catches: removing the `code.push(' ')` in `strip_sql_comments` -- this test
/// reds while every whitespace-padded fixture above stays green.
#[test]
fn a_block_comment_adjacent_to_a_token_still_separates_it_for_the_harness_reader() {
    assert_eq!(
        head_of_ledger(
            "INSERT/* which statement? */INTO/**/storage_schema_migrations\
             (version,/* name */name)VALUES(60,'060_adjacent');\n"
        ),
        (60, "060_adjacent".to_string()),
        "a reader that fuses the tokens around a block comment sees no statement here"
    );
}

/// The live-ledger continuity check compares the SET, not its SIZE.
///
/// The check this replaced asserted `count(DISTINCT version) == head`, and the
/// review refuted it with two edits that keep every count intact: delete
/// migration 45, insert `(0, '000_substitute')`. `version` is `BIGINT PRIMARY
/// KEY` with no positive domain, so the database accepts that row; `MAX(version)`
/// and the distinct count are both unchanged, so the old check passed on a
/// ledger missing a migration (#511).
///
/// Catches: any return to a count/max-based comparison. Replacing the set logic
/// in `ledger_continuity_violation` with `applied.len() == head` reds the
/// punctured case below while leaving the intact case green.
#[test]
fn the_ledger_continuity_check_rejects_a_punctured_ledger_of_the_right_size() {
    let intact = (1..=59)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(ledger_continuity_violation(&intact, 59), None);

    // The exact refutation from review: drop 45, add 0. Same count, same MAX.
    let punctured = std::iter::once(0)
        .chain((1..=59).filter(|v| *v != 45))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        punctured.split(',').count(),
        intact.split(',').count(),
        "the fixture must keep the row count identical, or it proves nothing"
    );
    let violation = ledger_continuity_violation(&punctured, 59)
        .expect("a ledger missing migration 45 must be refused");
    assert!(
        violation.contains('0'),
        "the refusal must name the out-of-range row: {violation}"
    );
}

/// Each continuity failure mode is named, not collapsed into one message.
#[test]
fn the_ledger_continuity_check_names_what_is_wrong() {
    // Behind the head: a partially applied schema wearing a correct head row.
    let short = (1..=58)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let violation =
        ledger_continuity_violation(&short, 59).expect("a ledger short of the head is refused");
    assert!(
        violation.contains("59"),
        "the refusal must name the missing migration: {violation}"
    );

    // Above the head: migrated by some other build than the one under test.
    let ahead = (1..=60)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        ledger_continuity_violation(&ahead, 59).is_some(),
        "a ledger ahead of the embedded SQL is a real finding, not a pass"
    );

    // An empty ledger is not an empty result.
    assert!(
        ledger_continuity_violation("", 59).is_some(),
        "an empty ledger must be refused, not read as 'nothing wrong'"
    );

    // A non-numeric field is refused rather than silently skipped.
    assert!(
        ledger_continuity_violation("1,two,3", 3).is_some(),
        "an unparseable version must be refused, not dropped"
    );
}

/// No second hard-coded migration identity may live in the scenario file.
///
/// Catches: a future slice re-introducing a pinned migration name or
/// `<version>:<name>` marker anywhere in `storage.rs` (a new "and migration 61
/// must be present" check, say) -- the exact shape that made this scenario fail
/// on its own bookkeeping instead of on the durability it exists to prove. The
/// only permitted way to name the head is `expected_head_migration`.
#[test]
fn the_scenario_file_carries_no_hand_written_migration_literal() {
    const SCENARIO_SOURCE: &str = include_str!("storage.rs");
    let bytes = SCENARIO_SOURCE.as_bytes();
    let mut offenders = Vec::new();
    for (index, window) in bytes.windows(4).enumerate().skip(1) {
        // A migration identity always reads as three digits then '_', quoted
        // (`"059_..."`) or preceded by its version (`"59:059_..."`).
        let looks_like_name = window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2].is_ascii_digit()
            && window[3] == b'_';
        let anchored = matches!(bytes[index - 1], b'"' | b'\'' | b':');
        if looks_like_name && anchored {
            let end = (index + 40).min(bytes.len());
            offenders.push(String::from_utf8_lossy(&bytes[index..end]).into_owned());
        }
    }
    assert!(
        offenders.is_empty(),
        "storage.rs must derive the schema head from ferrogate_storage, but it \
         names migrations directly: {offenders:?}"
    );
    assert!(
        SCENARIO_SOURCE.contains("ferrogate_storage::POSTGRES_SCHEMA_VERSION")
            && SCENARIO_SOURCE.contains("ferrogate_storage::POSTGRES_SCHEMA_NAME"),
        "the scenario must still read the derived head it is meant to assert against"
    );
}
