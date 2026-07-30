// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Database-free conformance proof that migration 59's SQL guards
// and their Rust mirror are ONE money domain (issue #352 review round 3 §1).
// The SQL half was previously asserted by constraint/index NAME only -- both by
// the live harness and by nothing at all offline -- so `CHECK (true)`, a
// non-unique index, or a regex widened to `^[0-9]*$` all left the repository
// green while Postgres and the memory backend disagreed about what a storable
// amount is. These tests read the DDL that actually ships and evaluate it.

use super::{is_canonical_atomic_amount, POSTGRES_SCHEMA_SQL};

/// The migration whose guards this file holds. Read out of the embedded SQL by
/// its ledger tuple so the tests cannot drift onto a different migration.
const MIGRATION_59_LEDGER: &str = "VALUES (59, '059_payment_attempt_amount_domains')";

/// The corpus is deliberately the SAME list
/// `payment_attempt_amount_domain_test.rs` uses against the Rust mirror, plus
/// the values the review named. Sharing it is the point: the two sides are
/// proven equal on the values that actually distinguish the candidate rules --
/// an empty string, a sign, an exponent, whitespace, hex, and the 20/21-digit
/// boundary at `u64::MAX`'s width.
const AMOUNT_CORPUS: [&str; 18] = [
    "",
    "0",
    "1",
    "250000",
    "+250000",
    "+250",
    "-1",
    "-5",
    "1e9",
    "2.5e5",
    "25.0",
    " 250000",
    " 250",
    "250 ",
    "0x10",
    "18446744073709551615",  // 20 digits: exactly u64::MAX
    "184467440737095516150", // 21 digits: wider than u64::MAX
    "00000000000000000000",  // 20 digits, leading zeros: canonical by width
];

/// The migration-59 `DO` block, verbatim from `sql/001_init_postgres.sql`.
///
/// Fails loudly when the block cannot be found rather than returning an empty
/// string: every assertion below is a `contains`-style claim over this text, so
/// a silently empty block would turn the whole file vacuous -- the exact defect
/// class this file exists to close.
fn migration_59() -> &'static str {
    let start = POSTGRES_SCHEMA_SQL
        .find(MIGRATION_59_LEDGER)
        .unwrap_or_else(|| panic!("migration ledger tuple {MIGRATION_59_LEDGER} is missing"));
    let rest = &POSTGRES_SCHEMA_SQL[start..];
    let end = rest
        .find("$$;")
        .expect("the migration-59 DO block must terminate with $$;");
    &rest[..end]
}

/// Collapse runs of whitespace so a statement can be pinned as one literal
/// regardless of how the DDL wraps its lines.
fn normalize_whitespace(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The regex literal a named `CHECK` constraint applies, read out of the DDL.
///
/// Panics when the constraint is absent or is no longer regex-shaped -- which
/// is what makes `CHECK (true)` red here: there is no pattern to extract, so
/// the domain claim cannot be restated by a test that never looked at it.
fn check_regex(constraint: &str) -> String {
    let block = migration_59();
    let start = block
        .find(&format!("ADD CONSTRAINT {constraint}"))
        .unwrap_or_else(|| panic!("migration 59 must add CHECK constraint {constraint}"));
    let statement = &block[start..];
    let statement_end = statement
        .find(';')
        .unwrap_or_else(|| panic!("{constraint} statement must terminate"));
    let statement = &statement[..statement_end];
    let pattern_start = statement.find("~ '").unwrap_or_else(|| {
        panic!("{constraint} no longer applies a regex; its body is: {statement}")
    }) + "~ '".len();
    let pattern = &statement[pattern_start..];
    let pattern_end = pattern
        .find('\'')
        .unwrap_or_else(|| panic!("{constraint}'s regex literal is unterminated"));
    let pattern = &pattern[..pattern_end];
    assert!(
        !pattern.is_empty(),
        "{constraint} applies an empty pattern, which matches nothing and cannot be the domain"
    );
    pattern.to_string()
}

/// One element of a supported pattern: a character class and how many times it
/// may repeat.
#[derive(Debug, Clone, Copy)]
struct Atom {
    class: Class,
    min: usize,
    max: usize,
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Digit,
    Literal(char),
}

impl Class {
    fn admits(self, value: char) -> bool {
        match self {
            Class::Digit => value.is_ascii_digit(),
            Class::Literal(expected) => value == expected,
        }
    }
}

/// Parse the subset of POSIX regex the money CHECKs are allowed to use:
/// `^`-anchored, `$`-terminated, a sequence of `[0-9]`/literal atoms each with
/// an optional `*`, `+`, `?`, `{m}` or `{m,n}` quantifier.
///
/// Anything outside that subset panics **naming the pattern**. That is the
/// intended behavior, not a gap: a rewrite into syntax this evaluator does not
/// model is a change to the money domain that no longer has a conformance
/// proof, and it must stop the build rather than be waved through by a matcher
/// that silently guesses. The reviewer's two mutations both stay inside the
/// subset (`^[0-9]*$`) or remove the pattern entirely (`CHECK (true)`), so both
/// fail as assertions rather than as parse panics.
fn parse_pattern(pattern: &str) -> Vec<Atom> {
    let chars: Vec<char> = pattern.chars().collect();
    assert_eq!(
        chars.first().copied(),
        Some('^'),
        "the amount domain must be anchored at the start: {pattern}"
    );
    assert_eq!(
        chars.last().copied(),
        Some('$'),
        "the amount domain must be anchored at the end: {pattern}"
    );

    let body = &chars[1..chars.len() - 1];
    let mut atoms = Vec::new();
    let mut index = 0;
    while index < body.len() {
        let class = if body[index] == '[' {
            let close = body[index..]
                .iter()
                .position(|character| *character == ']')
                .unwrap_or_else(|| panic!("unterminated character class in {pattern}"))
                + index;
            let class: String = body[index + 1..close].iter().collect();
            assert_eq!(
                class, "0-9",
                "only the digit class is modelled by this evaluator: {pattern}"
            );
            index = close + 1;
            Class::Digit
        } else {
            let character = body[index];
            assert!(
                !"^$.|()[]{}*+?\\".contains(character),
                "unsupported regex metacharacter {character:?} in {pattern}"
            );
            index += 1;
            Class::Literal(character)
        };

        let (min, max) = match body.get(index) {
            Some('*') => {
                index += 1;
                (0, usize::MAX)
            }
            Some('+') => {
                index += 1;
                (1, usize::MAX)
            }
            Some('?') => {
                index += 1;
                (0, 1)
            }
            Some('{') => {
                let close = body[index..]
                    .iter()
                    .position(|character| *character == '}')
                    .unwrap_or_else(|| panic!("unterminated quantifier in {pattern}"))
                    + index;
                let bounds: String = body[index + 1..close].iter().collect();
                index = close + 1;
                let (min, max) = match bounds.split_once(',') {
                    Some((low, "")) => (parse_bound(&bounds, low), usize::MAX),
                    Some((low, high)) => (parse_bound(&bounds, low), parse_bound(&bounds, high)),
                    None => {
                        let exact = parse_bound(&bounds, &bounds);
                        (exact, exact)
                    }
                };
                assert!(min <= max, "inverted quantifier {{{bounds}}} in {pattern}");
                (min, max)
            }
            _ => (1, 1),
        };
        atoms.push(Atom { class, min, max });
    }
    assert!(
        !atoms.is_empty(),
        "an anchored pattern with no atoms matches only the empty string: {pattern}"
    );
    atoms
}

fn parse_bound(bounds: &str, value: &str) -> usize {
    value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("non-numeric quantifier bound in {{{bounds}}}"))
}

/// Whether `value` matches the parsed pattern, with backtracking so a
/// multi-atom pattern is evaluated the way Postgres would evaluate it rather
/// than greedily.
fn pattern_matches(atoms: &[Atom], value: &str) -> bool {
    fn walk(atoms: &[Atom], value: &[char]) -> bool {
        let Some((atom, rest)) = atoms.split_first() else {
            return value.is_empty();
        };
        let available = value
            .iter()
            .take_while(|character| atom.class.admits(**character))
            .count();
        if available < atom.min {
            return false;
        }
        let ceiling = available.min(atom.max);
        // Longest-first, like a greedy engine, then give characters back.
        (atom.min..=ceiling)
            .rev()
            .any(|taken| walk(rest, &value[taken..]))
    }
    walk(atoms, &value.chars().collect::<Vec<_>>())
}

/// The blocker of #352 review round 3: the SQL `CHECK` and
/// [`is_canonical_atomic_amount`] are two independent statements of one money
/// domain, and nothing proved they agree.
///
/// Widen the CHECK to `^[0-9]*$` -- dropping only the 20-digit bound, the
/// mutation the review applied by hand -- and this test reds on `""` and on the
/// 21-digit amount: Postgres would store what the memory backend refuses, which
/// is precisely the #188 divergence. Replace the body with `CHECK (true)` and
/// [`check_regex`] finds no pattern and panics naming the constraint.
///
/// No database is involved: the assertion is over the DDL that ships in the
/// binary (`POSTGRES_SCHEMA_SQL`), so it runs in every `cargo test` rather than
/// only in a live scenario.
#[test]
fn the_atomic_amount_check_and_the_rust_mirror_are_the_same_domain() {
    let pattern = check_regex("payment_attempts_atomic_amount_canonical");
    let atoms = parse_pattern(&pattern);

    let mut accepted = 0;
    let mut rejected = 0;
    for value in AMOUNT_CORPUS {
        let sql_admits = pattern_matches(&atoms, value);
        let rust_admits = is_canonical_atomic_amount(value);
        assert_eq!(
            sql_admits, rust_admits,
            "the SQL CHECK {pattern:?} and is_canonical_atomic_amount disagree about {value:?}: \
             postgres admits={sql_admits}, rust admits={rust_admits}"
        );
        if rust_admits {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    // Anti-vacuity: a corpus that is all-accepted or all-rejected would be
    // satisfied by a constant rule on either side.
    assert!(
        accepted >= 4 && rejected >= 4,
        "the corpus must separate the two outcomes: {accepted} accepted, {rejected} rejected"
    );
}

/// `settled_atomic_amount` is written by the settlement transition, is
/// nullable, and carries the same domain. Both halves matter: the same regex
/// (so a widened copy cannot slip in on the column an attacker-influenced value
/// actually reaches) and the `IS NULL OR` disjunction (so an unsettled attempt
/// stays storable).
#[test]
fn the_settled_amount_check_is_the_same_domain_and_still_admits_null() {
    let atomic = check_regex("payment_attempts_atomic_amount_canonical");
    let settled = check_regex("payment_attempts_settled_amount_canonical");
    assert_eq!(
        atomic, settled,
        "both money columns must state ONE domain; a second, slightly-different \
         'canonical' is how a value passes one layer and is rejected by the next"
    );
    let block = normalize_whitespace(migration_59());
    assert!(
        block.contains("CHECK (settled_atomic_amount IS NULL OR settled_atomic_amount ~"),
        "the settled-amount CHECK must admit NULL for an unsettled attempt: {block}"
    );
}

/// The credits column is an integer, so its guard is a comparison rather than a
/// regex -- pinned as the constraint BODY for the same reason: `conname` alone
/// cannot see `CHECK (true)`.
#[test]
fn the_credits_amount_check_body_forbids_a_negative_ledger_amount() {
    let block = normalize_whitespace(migration_59());
    assert!(
        block.contains(
            "ADD CONSTRAINT payment_attempts_credits_amount_non_negative \
             CHECK (credits_amount IS NULL OR credits_amount >= 0)"
        ),
        "migration 59 must keep the credits-amount guard as a body, not just a name: {block}"
    );
}

/// The double-capture guard, pinned as the whole statement.
///
/// `pg_indexes` reports count 1 for a plain, unfiltered `CREATE INDEX` under
/// the same name, so the live name check could not see either half of what
/// makes this index load-bearing: UNIQUE (one on-chain transfer backs at most
/// one attempt, serialized where two concurrent settles actually race) and the
/// partial `WHERE` (so the many unsettled attempts sharing NULL are unaffected
/// and the migration does not fail on them).
#[test]
fn the_transaction_signature_index_is_unique_and_partial() {
    let block = normalize_whitespace(migration_59());
    assert!(
        block.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_attempts_transaction_signature \
             ON payment_attempts(transaction_signature) \
             WHERE transaction_signature IS NOT NULL;"
        ),
        "migration 59's double-capture guard must stay a partial UNIQUE index: {block}"
    );
}

/// The evaluator itself is falsifiable: it must reject what a naive
/// "contains only digits" check would accept and accept the full `u64` width.
///
/// Without this, a matcher that returned `is_canonical_atomic_amount(value)`
/// under another name would make the conformance test above tautological.
#[test]
fn the_pattern_evaluator_models_the_quantifier_it_reads() {
    let bounded = parse_pattern("^[0-9]{1,20}$");
    assert!(pattern_matches(&bounded, "0"));
    assert!(pattern_matches(&bounded, "18446744073709551615"));
    assert!(!pattern_matches(&bounded, ""));
    assert!(!pattern_matches(&bounded, "184467440737095516150"));
    assert!(!pattern_matches(&bounded, "+1"));

    // The reviewer's mutation: the same class, no upper bound. The evaluator
    // must see the difference, or the conformance test cannot.
    let widened = parse_pattern("^[0-9]*$");
    assert!(pattern_matches(&widened, ""));
    assert!(pattern_matches(&widened, "184467440737095516150"));

    // Backtracking, not greed: the trailing atom must still find its character.
    let split = parse_pattern("^[0-9]*5$");
    assert!(pattern_matches(&split, "125"));
    assert!(!pattern_matches(&split, "126"));
}
