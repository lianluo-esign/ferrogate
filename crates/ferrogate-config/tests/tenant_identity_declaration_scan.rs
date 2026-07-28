// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Repository-wide guard that every declared API key in the tree states a tenant identity (#540), across all four dialects that spell one.

//! The guard #540 shipped without (review finding 5).
//!
//! #540 flipped `[tenancy] implicit_platform_operator` to `false`, so an API
//! key that declares neither `organization_id` nor `platform_operator` is
//! refused at load and refused at authentication. The change swept 185
//! `[[api_keys]]` TOML blocks -- and then four more fixtures landed in the
//! other dialects and stopped four `ferrogate-gateway` snapshot tests
//! (`f2fd100`), one `ferrogate-cli` e2e (`3487459`), nine `ferrogate-test`
//! scenario configs (`60cdc14`) and the two README quickstarts, because the
//! sweep was a one-off script that walked one dialect and was never committed.
//! "The verifier now reports 0 undeclared" is only worth something if the
//! verifier is in the tree.
//!
//! # What it scans, and the honest ceiling of a text scan
//!
//! [`scan`] is a pure function of the source text, in the shape #480's
//! transaction-pin scan and #495's probe-env audit established, so the
//! detection logic is itself testable against synthetic inputs rather than only
//! against whatever the repository happens to contain today. Four dialects --
//! every one `Config` can be built from:
//!
//! * **TOML** -- a `[[api_keys]]` table array. This is the dialect the original
//!   sweep walked, and scanning *every text file* rather than `**/*.toml` is
//!   the point: 282 of the ~291 blocks live inside Rust raw strings, so a
//!   `.toml`-only walk would report zero, vacuously.
//! * **Caddyfile** -- an `api_key <id> { ... }` block, wherever it appears,
//!   including inside a fenced code block in `README.md`. That is exactly where
//!   two of the four misses were, and a copied quickstart that refuses to start
//!   is the worst place to find out.
//! * **JSON** -- an object literal that names `"id"`, one of
//!   `"key"`/`"key_hash"`/`"key_env"`, and either `"scopes"` (the typed
//!   `ApiKey` fixture shape) or a nearby `/admin/v1/api-keys` route literal
//!   (the Admin API mutation shape). `id` may be a string literal or a Rust
//!   expression; expressions are reported as `<dynamic:...>` instead of making
//!   the whole body invisible. This covers `serde_json::from_value` fixtures
//!   and POST/PUT/PATCH request bodies, including full-replacement bodies that
//!   omit `scopes`.
//! * **YAML** -- an `api_keys:` sequence whose items name `id` and a key field.
//!   Added by the #540 rework 2 (review finding 4): `Config::from_yaml_str`
//!   exists, `Config::load` dispatches on `.yaml`/`.yml`, `POST
//!   /admin/v1/config/validate` accepts a `config_yaml` body, and #540's own
//!   refusal message says "In TOML or YAML" -- so a YAML `api_keys:` list was a
//!   live way to write an undeclared key that all three earlier arms were blind
//!   to. The item must carry a key field (`key`/`key_env`/`key_hash`), which is
//!   what tells a FerroGate `[[api_keys]]` entry apart from the *auth
//!   service's* own `api_keys:` list in `config/auth-service.example.yaml`,
//!   whose items spell the secret `secret:` and are a different schema
//!   entirely.
//!
//! Escaped one-line spellings are read too (#540 rework 2, review minor 6): a
//! physical line is split on the two-character sequence `\n` and `\"` is
//! unescaped, so a whole TOML block or Caddyfile `api_key` block written as a
//! single Rust string literal -- live in `caddyfile/parser_tests.rs`, and the
//! shape that made two deliberate fixtures invisible to the first cut of this
//! scan -- is read as the several lines it means. Line numbers stay physical,
//! so a report still points at a line an editor can open.
//!
//! **Stated limits.** A key assembled at runtime from parts, or built as a Rust
//! struct literal with `..Default::default()`, is invisible to a text scan and
//! is not audited here; those are held by `Config::validate` and by
//! `Config::ensure_api_key_declares_tenant_identity` on the mint path, which
//! refuse them at the moment they are used. Also not modelled, and named rather
//! than implied away: TOML's inline `api_keys = [{ ... }]` array-of-tables
//! spelling (no instance in the tree today), and escape sequences other than
//! `\n` and `\"`. A JSON body without `scopes` is recognized as an Admin API
//! mutation only when its route literal is within
//! [`JSON_API_KEY_ROUTE_CONTEXT_LINES`] physical lines of the object; a helper
//! that assembles both route and body in distant functions is runtime-built and
//! belongs to the validator boundary, not this lexical scan. A *fifth* dialect
//! arriving later is likewise invisible -- this scan cannot know about a
//! spelling that does not exist yet.
//!
//! # Deliberately undeclared fixtures
//!
//! A test that proves the refusal fires needs a key that declares nothing. Such
//! a block says so, in a comment inside it or just above it, with the marker
//! [`DELIBERATE_MARKER`] -- so the exemption travels with the fixture instead of
//! living in a list that goes stale when the fixture moves. Blocks in files this
//! change could not edit (another crate owns them, or the format has no
//! comments) are listed in [`UNMARKED_EXEMPTIONS`] with the reason and the
//! number of blocks each excuses, which is a debt list and is meant to shrink.

use std::path::{Path, PathBuf};

/// The in-source opt-out. A block carrying this is a fixture whose whole
/// purpose is to be undeclared.
const DELIBERATE_MARKER: &str = "#540-undeclared-on-purpose";

/// How far above a block's first line the marker may sit, so a doc comment on
/// the test that owns the fixture can carry it.
///
/// The window is additionally clipped to the gap since the *previous*
/// declaration and to the block's own last line (#540 rework 2, review minor
/// 4). Before that it was a flat +/-20 lines around the header, so one marked
/// fixture licensed every undeclared block within 20 lines in either direction
/// -- which is a short distance in a file of back-to-back fixtures, and the
/// review found a live instance of exactly that in `config/tests.rs`.
const MARKER_LOOKBEHIND_LINES: usize = 20;

/// Route context used to distinguish an Admin API key mutation from unrelated
/// JSON `{id, key}` objects such as permissions and virtual-key responses.
///
/// The farthest current mutation fixture puts the route five physical lines
/// beyond the object's closing brace. Eight leaves formatting room while still
/// requiring the route and body to be one local request expression.
const JSON_API_KEY_ROUTE_CONTEXT_LINES: usize = 8;

/// Why a block appears in [`UNMARKED_EXEMPTIONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exemption {
    /// Being undeclared is the fixture's entire content, and the format has no
    /// comment syntax to carry the marker.
    Deliberate,
    /// A live defect, reported rather than endorsed. The fixture should declare
    /// an identity; the edit belongs to a crate this lane does not own. Counted
    /// and capped by [`debt_is_not_growing`], which is the only thing that
    /// keeps a list like this from becoming a place to park findings.
    Debt,
}

/// Undeclared blocks this change could not annotate, each with the reason.
///
/// `(repo-relative path, key id, how many blocks with that id, kind, reason)`.
/// Matched on the pair, with the count bounding how many occurrences one entry
/// may excuse (#540 rework 2, review minor 5) -- so a second undeclared block
/// sneaking into an already-exempt file is a violation rather than a free ride.
/// Line numbers may move freely.
///
/// **Reasons are durable, not session-scoped** (review minor 7). The previous
/// round justified nine of twelve entries with "a parallel slice owns this
/// directory this session", a reason that expired the moment that slice landed
/// and that no test could ever catch expiring. Each entry now states a fact
/// about the repository -- which crate owns the file, or which format cannot
/// carry a comment -- and every `Debt` entry is counted against a cap that may
/// only go down.
const UNMARKED_EXEMPTIONS: &[(&str, &str, usize, Exemption, &str)] = &[
    (
        "tests/fixtures/governed-decisions/auth__tenant-identity-required.json",
        "key-undeclared",
        1,
        Exemption::Deliberate,
        "the conformance fixture FOR the tenant_identity_required refusal -- being undeclared is \
         its entire content, and JSON has no comment syntax to carry the marker",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "legacy-admin",
        1,
        Exemption::Deliberate,
        "a pre-#515 key under the `implicit_platform_operator = true` opt-in, which is what that \
         test is for. Unmarked because the fixture is owned by ferrogate-cli, not by this crate; \
         the marker belongs in that file and is a one-line change there",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "legacy",
        1,
        Exemption::Deliberate,
        "the `null` declaration half of the declared/effective pair; same ownership as the entry \
         above",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "unscoped",
        1,
        Exemption::Deliberate,
        "the POST body #540 must answer 400 to; same ownership as the entry above",
    ),
    (
        "crates/ferrogate-cli/tests/check_command.rs",
        "bootstrap",
        1,
        Exemption::Deliberate,
        "the config `ferrogate check` must refuse; same ownership as the entries above",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "admin",
        1,
        Exemption::Debt,
        "an `ApiKey` fixture that never reaches `Config::validate`, so nothing refuses it today. \
         It should declare `platform_operator = true`. Owned by ferrogate-cli",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "chat",
        1,
        Exemption::Debt,
        "a chat-only fixture that should name a tenant (#563's argument). Owned by ferrogate-cli",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "off",
        1,
        Exemption::Debt,
        "see the `admin` entry. Owned by ferrogate-cli",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "old",
        1,
        Exemption::Debt,
        "see the `admin` entry. Owned by ferrogate-cli",
    ),
    (
        "crates/ferrogate-cli/tests/ai_proxy_runtime.rs",
        "client",
        1,
        Exemption::Debt,
        "a PATCH body that omits organization_id after a create that declared it. It passes today \
         only because `apply_tenant_refs_to_api_keys` re-applies the binding from the tenants \
         documents -- a re-merge two layers below the request, which also means `PUT \
         /admin/v1/api-keys/{id}` cannot change an existing key's tenant. Owned by ferrogate-cli",
    ),
];

/// The `Debt` entries are known live defects parked in a passing test. The cap
/// is the number of them at the time of writing; it may only ever go down.
///
/// A test that tolerates a defect has to say how many it is tolerating, or the
/// list becomes the place findings go to be forgotten -- which is what review
/// minor 7 called out.
const MAX_KNOWN_UNDECLARED_DEBT: usize = 5;

/// Directories the walk never enters: build output, vendored third-party
/// sources, dependency trees, and sibling agent worktrees under `.claude/`.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".claude",
    "target",
    "vendor",
    "node_modules",
    "dist",
    "build",
];

/// The floor each dialect's arm must find in the repository, so the guard has a
/// positive control rather than a pass reached by construction (#540 rework 2,
/// review finding 3).
///
/// These count **every** api-key declaration the arm sees, declared and
/// undeclared alike -- not the undeclared ones. A floor on undeclared blocks
/// would shrink every time somebody correctly annotates a fixture, which is the
/// opposite of the incentive this file wants; a floor on all declarations only
/// grows.
///
/// Measured before the route-aware JSON expansion in this rework, where `scan`
/// found 311 TOML, 22 Caddyfile, 60 JSON and 37 YAML declarations across 1444
/// text files. The JSON count only grows when the no-`scopes` and dynamic-id
/// mutation bodies become visible. Each floor sits well below that measurement
/// so ordinary churn does not red it; a count that falls below one means the
/// guard has stopped seeing part of the tree, and the number must be
/// re-measured, never lowered on faith.
///
/// Mutations these catch: narrowing `scan` to `scan_toml` alone zeroes three of
/// the four; dropping `crates/` from the walk takes TOML to 32 and Caddyfile to
/// 3; dropping `tests/` takes JSON to 22; dropping `tools/` takes YAML to 4.
/// Before this, all of those left every assertion green, because the only
/// floors were on files walked and 43% of the tree could vanish unnoticed.
const DIALECT_FLOORS: &[(Dialect, usize)] = &[
    (Dialect::Toml, 260),
    (Dialect::Caddyfile, 14),
    (Dialect::Json, 40),
    (Dialect::Yaml, 24),
];

/// One file per top-level directory an api-key declaration lives in, with the
/// dialect it must yield.
///
/// A total floor cannot catch a walk that stops entering a small directory:
/// dropping `config/` costs three TOML declarations out of 311 and no count
/// would notice, yet it is exactly where the two operator-facing example
/// configs live. These anchors are per-directory positive controls -- skip
/// `config/`, `docs/`, `tests/`, `tools/`, or everything but `crates/`, and the
/// corresponding entry reds by name.
///
/// They double as the Caddyfile arm's repository anchor, which review finding 3
/// pointed out it had never had: its only proof was one synthetic string.
const ANCHORS: &[(&str, Dialect)] = &[
    ("config/ferrogate.example.toml", Dialect::Toml),
    ("README.md", Dialect::Caddyfile),
    ("docs/openapi/admin-api.openapi.json", Dialect::Json),
    (
        "tests/fixtures/governed-decisions/auth__tenant-identity-required.json",
        Dialect::Json,
    ),
    ("tools/ferrogate-test/src/storage.rs", Dialect::Yaml),
    (
        "crates/ferrogate-config/src/config/tests.rs",
        Dialect::Caddyfile,
    ),
];

/// JSON declarations named by the #540 review, pinned to their actual source
/// files rather than inferred from the synthetic controls below.
///
/// The first two are declared controls whose identity deletion must remain
/// visible. The remaining four are deliberately undeclared refusal probes;
/// their markers may exempt them only after the scan has found them.
const JSON_MUTATION_ANCHORS: &[(&str, &str, bool)] = &[
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "k-cross",
        true,
    ),
    (
        "crates/ferrogate-cli/tests/vpc_offline_loop_e2e.rs",
        "<dynamic:id>",
        true,
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "k1",
        false,
    ),
    (
        "crates/ferrogate-cli/tests/tenant_suspension_e2e.rs",
        "ak-susp",
        false,
    ),
    (
        "tools/ferrogate-test/src/scenarios.rs",
        "box4-cross-project",
        false,
    ),
    (
        "tools/ferrogate-test/src/scenarios.rs",
        "box4-consistent",
        false,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dialect {
    Toml,
    Caddyfile,
    Json,
    Yaml,
}

/// One api-key declaration, in any dialect, declared or not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Declaration {
    dialect: Dialect,
    id: String,
    /// 1-based physical line of the block's first line.
    line: usize,
    /// 1-based physical line of the block's last line.
    end_line: usize,
    /// It names `organization_id` or `platform_operator`, either way.
    declares_identity: bool,
}

/// One logical line: the text to scan, plus the physical line it came from.
///
/// A physical line containing the escape `\n` yields several logical lines, all
/// reporting the physical line they were written on.
struct SourceLine {
    number: usize,
    text: String,
}

fn logical_lines(source: &str) -> Vec<SourceLine> {
    let mut lines = Vec::new();
    for (index, physical) in source.lines().enumerate() {
        let number = index + 1;
        if physical.contains("\\n") {
            for piece in physical.split("\\n") {
                lines.push(SourceLine {
                    number,
                    text: piece.replace("\\\"", "\""),
                });
            }
        } else {
            lines.push(SourceLine {
                number,
                text: physical.to_string(),
            });
        }
    }
    lines
}

/// Every api-key declaration in `source`, in any of the four dialects.
///
/// Pure: no filesystem, no exemptions. Exemptions are applied by the caller, so
/// the unit cases below can assert on detection without a marker silencing the
/// very thing they are testing.
fn scan(source: &str) -> Vec<Declaration> {
    let lines = logical_lines(source);
    let mut declarations = scan_toml(&lines);
    declarations.extend(scan_caddyfile(&lines));
    declarations.extend(scan_json(&lines));
    declarations.extend(scan_yaml(&lines));
    // Source order, so a caller can reason about "the first one" and so a
    // failure message reads top to bottom like the file it names.
    declarations.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.dialect.cmp(&right.dialect))
            .then_with(|| left.id.cmp(&right.id))
    });
    declarations
}

/// The subset that states no tenant identity -- what the guard is about.
fn undeclared(source: &str) -> Vec<Declaration> {
    scan(source)
        .into_iter()
        .filter(|declaration| !declaration.declares_identity)
        .collect()
}

fn scan_toml(lines: &[SourceLine]) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !is_toml_api_keys_header(&lines[index].text) {
            index += 1;
            continue;
        }
        let start = index;
        let mut id = String::new();
        let mut declared = false;
        // The block ends at its last FIELD, not at wherever the walk stopped:
        // the blank lines and comments between two `[[api_keys]]` blocks belong
        // to the second one, and the marker for the second is usually written
        // exactly there. Ending the first block on top of it would swallow the
        // marker the moment `is_marked_deliberate` started clipping windows at
        // the previous declaration.
        let mut last_field = start;
        let mut cursor = index + 1;
        while cursor < lines.len() {
            let line = lines[cursor].text.trim();
            // The next table header ends the block; so does the end of the Rust
            // raw string the block is embedded in.
            if line.starts_with('[')
                || line.starts_with("\"#")
                || line.ends_with("\"#;")
                || line.ends_with("\"#,")
            {
                break;
            }
            if !line.is_empty() && !line.starts_with('#') && !line.starts_with("//") {
                last_field = cursor;
            }
            if let Some(value) = toml_string_value(line, "id") {
                if id.is_empty() {
                    id = value;
                }
            }
            if toml_declares(line, "organization_id") || toml_declares(line, "platform_operator") {
                declared = true;
            }
            cursor += 1;
        }
        declarations.push(Declaration {
            dialect: Dialect::Toml,
            id: if id.is_empty() {
                "<unnamed>".to_string()
            } else {
                id
            },
            line: lines[start].number,
            end_line: lines[last_field].number,
            declares_identity: declared,
        });
        index = cursor.max(start + 1);
    }
    declarations
}

/// `[[api_keys]]`, and the spaced spelling `[[ api_keys ]]` TOML also accepts.
fn is_toml_api_keys_header(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(rest) = trimmed.strip_prefix("[[") else {
        return false;
    };
    let Some(rest) = rest.strip_suffix("]]") else {
        return false;
    };
    rest.trim() == "api_keys"
}

fn toml_declares(line: &str, field: &str) -> bool {
    line.strip_prefix(field)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

fn toml_string_value(line: &str, field: &str) -> Option<String> {
    let rest = line.strip_prefix(field)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn scan_caddyfile(lines: &[SourceLine]) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some((id, inline_body)) = caddyfile_block_header(&lines[index].text) else {
            index += 1;
            continue;
        };
        let start = index;
        // A one-line block (`api_key k { key s }`) is a shape the earlier arm
        // could not see at all, because it required the line to END with `{`.
        if let Some(body) = inline_body {
            declarations.push(Declaration {
                dialect: Dialect::Caddyfile,
                id,
                line: lines[start].number,
                end_line: lines[start].number,
                declares_identity: caddyfile_body_declares(&body),
            });
            index += 1;
            continue;
        }
        let mut depth = 1usize;
        let mut declared = false;
        let mut cursor = index + 1;
        while cursor < lines.len() && depth > 0 {
            let line = &lines[cursor].text;
            for character in line.chars() {
                match character {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            if depth > 0 && caddyfile_body_declares(line) {
                declared = true;
            }
            cursor += 1;
        }
        declarations.push(Declaration {
            dialect: Dialect::Caddyfile,
            id,
            line: lines[start].number,
            end_line: lines[cursor.saturating_sub(1).max(start)].number,
            declares_identity: declared,
        });
        index = cursor.max(start + 1);
    }
    declarations
}

fn caddyfile_body_declares(body: &str) -> bool {
    body.split_whitespace()
        .any(|word| word == "organization_id" || word == "platform_operator")
}

/// `api_key <id> {` opens a key block, and `api_key "<id>" { ... }` is the same
/// block with the id quoted -- a spelling the parser accepts and the earlier arm
/// rejected outright. `api_key {env.OPENAI_API_KEY}` is the *provider's*
/// credential directive and is not a key block, which is why the name has to be
/// a real token rather than merely "something before the brace".
///
/// Returns the id, and the body when the whole block sits on one line.
fn caddyfile_block_header(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("api_key ")?;
    let brace = rest.find('{')?;
    let raw_id = rest[..brace].trim();
    let id = raw_id.trim_matches('"').trim();
    if id.is_empty() {
        return None;
    }
    let after = &rest[brace + 1..];
    match after.find('}') {
        Some(close) => Some((id.to_string(), Some(after[..close].to_string()))),
        None => Some((id.to_string(), None)),
    }
}

fn scan_json(lines: &[SourceLine]) -> Vec<Declaration> {
    let mut characters: Vec<char> = Vec::new();
    let mut physical_line: Vec<usize> = Vec::new();
    for line in lines {
        for character in line.text.chars() {
            characters.push(character);
            physical_line.push(line.number);
        }
        characters.push('\n');
        physical_line.push(line.number);
    }

    struct Frame {
        start: usize,
        line: usize,
        children: Vec<(usize, usize)>,
    }

    let mut declarations = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    for (index, character) in characters.iter().enumerate() {
        match character {
            '{' => stack.push(Frame {
                start: index,
                line: physical_line[index],
                children: Vec::new(),
            }),
            '}' => {
                let Some(frame) = stack.pop() else {
                    continue;
                };
                // #540 rework 2, review minor 6: the earlier arm kept only the
                // most recent `{`, so ANY api-key object containing a nested
                // sub-object was invisible -- the inner brace reset the opening
                // position and the outer object was never examined. A stack
                // sees every object; the object's own text with its children
                // removed is what decides whether it is an api key, so a
                // function body wrapping one is not mistaken for one.
                let object = shallow_text(&characters, frame.start, index, &frame.children);
                let route_context =
                    json_api_key_route_is_near(lines, frame.line, physical_line[index]);
                if let Some(id) = json_api_key_id(&object, route_context) {
                    declarations.push(Declaration {
                        dialect: Dialect::Json,
                        id,
                        line: frame.line,
                        end_line: physical_line[index],
                        declares_identity: object.contains("\"organization_id\"")
                            || object.contains("\"platform_operator\""),
                    });
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push((frame.start, index));
                }
            }
            _ => {}
        }
    }
    declarations
}

/// The object's own text, with every completed child object removed.
fn shallow_text(
    characters: &[char],
    start: usize,
    end: usize,
    children: &[(usize, usize)],
) -> String {
    let mut text = String::new();
    let mut cursor = start;
    for (child_start, child_end) in children {
        if *child_start > cursor {
            text.extend(&characters[cursor..*child_start]);
        }
        cursor = cursor.max(child_end + 1);
    }
    if cursor <= end {
        text.extend(&characters[cursor..=end]);
    }
    text
}

/// Classify one shallow JSON object as an API-key declaration.
///
/// `scopes` is a strong structural signal for typed `ApiKey` fixtures. Admin
/// mutation bodies do not require it, so an exact route literal nearby is the
/// second signal. Requiring one of those two avoids sweeping unrelated
/// permission and virtual-key objects that also happen to spell `{id, key}`.
fn json_api_key_id(object: &str, route_context: bool) -> Option<String> {
    if !object.contains("\"id\"") || (!object.contains("\"scopes\"") && !route_context) {
        return None;
    }
    if !object.contains("\"key\"")
        && !object.contains("\"key_hash\"")
        && !object.contains("\"key_env\"")
    {
        return None;
    }
    let rest = &object[object.find("\"id\"")? + 4..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }

    // Rust `json!` fixtures commonly use `"id": id` or `"id": CONST`. The
    // id is diagnostic metadata, not what determines whether the object is a
    // key, so preserve the expression as a stable label rather than dropping
    // the declaration. Stop at the field delimiter; complicated expressions
    // may be abbreviated, which is fine because file+line remains authoritative.
    let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
    let expression = rest[..end].trim();
    (!expression.is_empty()).then(|| format!("<dynamic:{expression}>"))
}

fn json_api_key_route_is_near(lines: &[SourceLine], start_line: usize, end_line: usize) -> bool {
    let first = start_line.saturating_sub(JSON_API_KEY_ROUTE_CONTEXT_LINES);
    let last = end_line.saturating_add(JSON_API_KEY_ROUTE_CONTEXT_LINES);
    lines.iter().any(|line| {
        (first..=last).contains(&line.number) && line.text.contains("/admin/v1/api-keys")
    })
}

fn scan_yaml(lines: &[SourceLine]) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].text.trim() != "api_keys:" {
            index += 1;
            continue;
        }
        let list_indent = indent_of(&lines[index].text);
        index += 1;
        while index < lines.len() {
            let text = &lines[index].text;
            if text.trim().is_empty() || text.trim_start().starts_with('#') {
                index += 1;
                continue;
            }
            let item_indent = indent_of(text);
            if item_indent <= list_indent {
                break;
            }
            let Some(first_field) = text.trim_start().strip_prefix("- ") else {
                break;
            };
            let start = index;
            let mut fields = vec![first_field.to_string()];
            let mut last_field = start;
            index += 1;
            // The item's own fields are the lines below it that are indented
            // further than the dash; a sibling item or a dedent ends it.
            let mut field_indent = None;
            while index < lines.len() {
                let line = &lines[index].text;
                if line.trim().is_empty() {
                    index += 1;
                    continue;
                }
                let indent = indent_of(line);
                if indent <= item_indent {
                    break;
                }
                last_field = index;
                let field_indent = *field_indent.get_or_insert(indent);
                // Only the item's OWN keys count: `tenant:\n  organization_id:`
                // is a nested map and says nothing about this key's identity.
                if indent == field_indent {
                    fields.push(line.trim().to_string());
                }
                index += 1;
            }
            let end = lines[last_field].number;
            if let Some(id) = yaml_api_key_id(&fields) {
                declarations.push(Declaration {
                    dialect: Dialect::Yaml,
                    id,
                    line: lines[start].number,
                    end_line: end,
                    declares_identity: fields.iter().any(|field| {
                        yaml_field_value(field, "organization_id").is_some()
                            || yaml_field_value(field, "platform_operator").is_some()
                    }),
                });
            }
        }
    }
    declarations
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// A YAML sequence item is a FerroGate api key when it names an `id` and one of
/// the three ways to spell the secret. The auth service's own `api_keys:` list
/// spells it `secret:` and is a different schema, so it is not swept in.
fn yaml_api_key_id(fields: &[String]) -> Option<String> {
    let has_secret = fields.iter().any(|field| {
        yaml_field_value(field, "key").is_some()
            || yaml_field_value(field, "key_env").is_some()
            || yaml_field_value(field, "key_hash").is_some()
    });
    if !has_secret {
        return None;
    }
    fields
        .iter()
        .find_map(|field| yaml_field_value(field, "id"))
}

fn yaml_field_value(field: &str, name: &str) -> Option<String> {
    let rest = field.trim().strip_prefix(name)?;
    let rest = rest.strip_prefix(':')?.trim();
    let value = rest.trim_matches('"').trim_matches('\'').trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// Whether `declarations[position]` carries the deliberate marker.
///
/// The window is the block itself plus the gap above it, bounded by
/// [`MARKER_LOOKBEHIND_LINES`] and by where the previous declaration ended
/// (#540 rework 2, review minor 4). Both bounds matter: without the lower one a
/// marker near the top of a 4,000-line file exempts everything after it;
/// without the upper one a marker *inside* one fixture exempts the fixture that
/// follows it, which is what the review found in `config/tests.rs`.
fn is_marked_deliberate(source: &str, declarations: &[Declaration], position: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let declaration = &declarations[position];
    let previous_end = declarations[..position]
        .iter()
        .map(|earlier| earlier.end_line)
        .max()
        .unwrap_or(0);
    let first = declaration.line.saturating_sub(1);
    // Clipped at the previous declaration, but never past this block's own
    // first line: several escaped blocks can share ONE physical line, and there
    // the clip would otherwise leave an empty window that no comment could ever
    // reach.
    let from = first
        .saturating_sub(MARKER_LOOKBEHIND_LINES)
        .max(previous_end)
        .min(first);
    let to = declaration.end_line.max(first + 1).min(lines.len());
    if from >= to {
        return false;
    }
    lines[from..to]
        .iter()
        .any(|line| line.contains(DELIBERATE_MARKER))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<crate> is two levels below the workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIPPED_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}

/// Every text file in the tree, as `(repo-relative path, contents)`.
fn repository_sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 500,
        "the walk found only {} files under {}; something is wrong with the root or the skip \
         list, and a scan that reads nothing reports zero violations",
        files.len(),
        root.display()
    );
    let mut sources = Vec::new();
    for path in files {
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue; // binary or unreadable: not a config dialect
        };
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        sources.push((relative, source));
    }
    assert!(
        sources.len() > 500,
        "only {} text files were read; the scan must actually read the tree",
        sources.len()
    );
    sources
}

/// The guard. Every api-key declaration in the tree either states a tenant
/// identity, carries the deliberate marker, or is listed with a reason.
///
/// Mutation this catches: delete any `platform_operator = true` /
/// `organization_id = "..."` line from a static declaration shape documented
/// above -- including the four fixtures the review found, the two READMEs, or
/// any of the ~300 others -- and this test names the file, the line, the dialect
/// and the key id. Runtime-assembled values remain the validator's boundary, as
/// stated in the module limits. This is deliberately NOT satisfiable by the
/// flip being reverted, because it never reads `TenancyConfig`: it is a
/// statement about the tree, not about the default.
///
/// And, since the #540 rework 2 (review finding 3), it is not satisfiable by
/// the walk quietly going blind either: [`DIALECT_FLOORS`] is a positive
/// control on what each arm actually found.
#[test]
fn every_api_key_declaration_in_the_tree_states_a_tenant_identity() {
    let sources = repository_sources();

    let mut violations = Vec::new();
    let mut seen: Vec<(Dialect, usize)> = DIALECT_FLOORS
        .iter()
        .map(|(dialect, _)| (*dialect, 0))
        .collect();
    let mut used: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();

    for (relative, source) in &sources {
        let declarations = scan(source);
        for (dialect, count) in seen.iter_mut() {
            *count += declarations
                .iter()
                .filter(|declaration| declaration.dialect == *dialect)
                .count();
        }
        for (position, declaration) in declarations.iter().enumerate() {
            if declaration.declares_identity {
                continue;
            }
            if is_marked_deliberate(source, &declarations, position) {
                continue;
            }
            let allowance = UNMARKED_EXEMPTIONS
                .iter()
                .find(|(path, id, ..)| *path == relative && *id == declaration.id);
            if let Some((path, id, count, ..)) = allowance {
                let used = used.entry((path, id)).or_insert(0);
                if *used < *count {
                    *used += 1;
                    continue;
                }
            }
            violations.push(format!(
                "{relative}:{} [{:?}] api key `{}` declares neither organization_id nor \
                 platform_operator",
                declaration.line, declaration.dialect, declaration.id
            ));
        }
    }

    for (dialect, floor) in DIALECT_FLOORS {
        let found = seen
            .iter()
            .find(|(seen_dialect, _)| seen_dialect == dialect)
            .map(|(_, count)| *count)
            .unwrap_or_default();
        assert!(
            found >= *floor,
            "the {dialect:?} arm found only {found} api-key declarations in the tree, below the \
             floor of {floor}. Either that dialect's arm has stopped matching, or the walk has \
             stopped reaching the files it lives in -- a scan that sees nothing reports no \
             violations. Re-measure before changing this number."
        );
    }

    for (path, dialect) in ANCHORS {
        let Some((_, source)) = sources.iter().find(|(relative, _)| relative == path) else {
            panic!(
                "the walk never reached {path}, which is this scan's anchor for the directory it \
                 lives in and for the {dialect:?} dialect; a directory that vanishes from the \
                 walk takes its declarations with it and reports zero violations"
            );
        };
        assert!(
            scan(source)
                .iter()
                .any(|declaration| declaration.dialect == *dialect),
            "{path} no longer yields a {dialect:?} api-key declaration; either the file changed \
             or that arm has stopped matching the shape it is written in"
        );
    }

    assert!(
        violations.is_empty(),
        "#540: an API key that declares neither organization_id nor platform_operator is refused \
         at load and refused at authentication, so a fixture or example in this shape is a test \
         that cannot run and a quickstart that cannot start. Declare each one \
         (`platform_operator = true` / `platform_operator on` for a key that administers every \
         tenant, `organization_id` for a key that belongs to one), or -- if being undeclared IS \
         what the fixture is for -- put `{DELIBERATE_MARKER}` in a comment inside it or just \
         above it.\n\n{}",
        violations.join("\n")
    );
}

/// The exact variable-id and no-`scopes` bodies that exposed the old JSON
/// classifier must stay visible. A marker is an exemption, not proof that the
/// declaration beside it was ever found, so the four deliberate bodies are
/// anchored here with the declared controls that review proposed mutating.
#[test]
fn the_reviewed_json_mutation_bodies_are_all_visible() {
    let sources = repository_sources();

    for (path, id, declares_identity) in JSON_MUTATION_ANCHORS {
        let source = sources
            .iter()
            .find(|(relative, _)| relative == path)
            .unwrap_or_else(|| panic!("the repository walk did not reach JSON anchor {path}"));
        let matches: Vec<_> = scan(&source.1)
            .into_iter()
            .filter(|declaration| {
                declaration.dialect == Dialect::Json
                    && declaration.id == *id
                    && declaration.declares_identity == *declares_identity
            })
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one JSON declaration `{id}` with declares_identity={declares_identity} in {path}, found {matches:?}"
        );
    }
}

/// The scan itself, against synthetic sources, so its reach is a claim that can
/// be checked rather than a property of whatever the tree contains today.
///
/// Mutation this catches: drop any one of the four dialect arms from [`scan`]
/// and the corresponding case reds. Before this file existed, a
/// `**/*.toml`-only verifier would have reported `0 undeclared` on a tree with
/// 282 blocks it could not see.
#[test]
fn the_scan_finds_an_undeclared_key_in_each_dialect_and_leaves_declared_ones_alone() {
    // A TOML block inside a Rust raw string, which is where 282 of the tree's
    // ~300 blocks live. These fixtures are undeclared on purpose and carry the
    // marker for the repository walk above -- `scan` itself never applies
    // exemptions, so they stay detectable here.
    let rust_raw_string = r##"
fn config() -> String {
    r#"
listen = "127.0.0.1:8080"

# #540-undeclared-on-purpose: the input the scan must detect
[[api_keys]]
id = "undeclared-toml"
name = "Undeclared"
key = "secret"

[[ api_keys ]]
id = "declared-toml"
name = "Declared"
key = "secret"
organization_id = "tenant-a"
"#.to_string()
}
"##;
    let toml_findings = undeclared(rust_raw_string);
    assert_eq!(
        toml_findings.len(),
        1,
        "exactly the undeclared block: {toml_findings:?}"
    );
    assert_eq!(toml_findings[0].dialect, Dialect::Toml);
    assert_eq!(toml_findings[0].id, "undeclared-toml");
    assert_eq!(
        scan(rust_raw_string).len(),
        2,
        "and the spaced `[[ api_keys ]]` spelling TOML also accepts is still a declaration"
    );

    // A Caddyfile block in a markdown fence -- the README shape the sweep
    // missed. The provider's own `api_key {env.X}` directive must not be read
    // as a key block.
    let markdown = r#"
```caddyfile
:8080 {
    ai_gateway {
        provider openai {
            api_key {env.OPENAI_API_KEY}
        }
        # #540-undeclared-on-purpose: the input the scan must detect
        api_key undeclared_caddy {
            key dev-secret
            scopes admin.read
        }
        api_key "declared_caddy" {
            key other-secret
            scopes admin.read
            platform_operator on
        }
    }
}
```
"#;
    let caddy_findings = undeclared(markdown);
    assert_eq!(
        caddy_findings.len(),
        1,
        "the provider credential directive is not a key block: {caddy_findings:?}"
    );
    assert_eq!(caddy_findings[0].dialect, Dialect::Caddyfile);
    assert_eq!(caddy_findings[0].id, "undeclared_caddy");
    assert_eq!(
        scan(markdown).len(),
        2,
        "and a quoted id is the same block, not an unreadable one"
    );

    // A JSON request body / `serde_json::from_value` fixture.
    let json_bodies = r#"
    // #540-undeclared-on-purpose: the input the scan must detect
    let created = post("/admin/v1/api-keys",
        r#_{"id":"undeclared-json","name":"C","key":"s","scopes":["chat.completions"]}_#);
    let scoped = post("/admin/v1/api-keys",
        r#_{"id":"declared-json","name":"D","key":"s","scopes":["chat.completions"],"organization_id":"tenant-a"}_#);
    let unrelated = json!({"id":"m1","object":"model","owned_by":"ferrogate"});
"#;
    let json_findings = undeclared(json_bodies);
    assert_eq!(
        json_findings.len(),
        1,
        "an object without a key field is not an api key: {json_findings:?}"
    );
    assert_eq!(json_findings[0].dialect, Dialect::Json);
    assert_eq!(json_findings[0].id, "undeclared-json");

    // #540-undeclared-on-purpose: the input the scan must detect
    let nested = r#"
    {"id":"nested-json","name":"N","key":"s","scopes":["chat.completions"],
     "metadata":{"created_by":"test"}}
"#;
    let nested_findings = undeclared(nested);
    assert_eq!(
        nested_findings.len(),
        1,
        "an api key with a nested sub-object is still an api key: {nested_findings:?}"
    );
    assert_eq!(nested_findings[0].id, "nested-json");

    // Admin mutation bodies are full replacements and do not require `scopes`.
    // The exact route distinguishes this from unrelated `{id, key}` JSON, and
    // a Rust expression in `id` is retained as a diagnostic label. These are
    // separate controls: restoring the old `scopes` requirement drops the
    // first; restoring the string-literal-only id parser drops the second.
    let no_scopes_mutation = r#"
    post(
        "/admin/v1/api-keys",
        json!({"id":"no-scopes-json","name":"N","key":"s","organization_id":"tenant-a"}),
    );
"#;
    let no_scopes = scan(no_scopes_mutation);
    assert_eq!(
        no_scopes.len(),
        1,
        "the route makes this a key body: {no_scopes:?}"
    );
    assert_eq!(no_scopes[0].id, "no-scopes-json");
    assert!(no_scopes[0].declares_identity);

    let unrelated_id_and_key =
        r#"let permission = json!({"id":"permission-a","key":"permission.read"});"#;
    assert!(
        scan(unrelated_id_and_key).is_empty(),
        "without scopes or a nearby api-key route, an unrelated id/key object is not a key"
    );

    // #540-undeclared-on-purpose: this is the dynamic-id mutation the scanner
    // must see, not a key that any gateway loads.
    let dynamic_id_mutation = r#"
    let body = json!({
        "id": id,
        "name": "Rotated key",
        "key": secret,
        "scopes": ["models.read"],
    });
    post("/admin/v1/api-keys", body);
"#;
    let dynamic = undeclared(dynamic_id_mutation);
    assert_eq!(
        dynamic.len(),
        1,
        "a variable id must not hide the body: {dynamic:?}"
    );
    assert_eq!(dynamic[0].id, "<dynamic:id>");

    // YAML: a live loader dialect (`Config::from_yaml_str`, and the
    // `config_yaml` body of POST /admin/v1/config/validate) that no arm could
    // see before.
    let yaml = r#"
listen: "127.0.0.1:8080"
api_keys:
  # #540-undeclared-on-purpose: the input the scan must detect
  - id: undeclared-yaml
    name: Undeclared
    key: secret
    scopes:
      - chat.completions
  - id: declared-yaml
    name: Declared
    key: secret
    organization_id: tenant-a
"#;
    let yaml_findings = undeclared(yaml);
    assert_eq!(
        yaml_findings.len(),
        1,
        "exactly the undeclared item: {yaml_findings:?}"
    );
    assert_eq!(yaml_findings[0].dialect, Dialect::Yaml);
    assert_eq!(yaml_findings[0].id, "undeclared-yaml");

    // The auth service's own `api_keys:` list is a different schema -- its
    // items spell the secret `secret:` and carry a nested `tenant:` map -- and
    // must not be swept into a guard about `ferrogate_config::ApiKey`.
    let auth_service_yaml = r#"
api_keys:
  - id: key-example
    name: Example gateway key
    secret: dev-secret
    enabled: true
    tenant:
      organization_id: org-example
    scopes:
      - models.read
"#;
    assert!(
        scan(auth_service_yaml).is_empty(),
        "the auth service's key list is not a FerroGate [[api_keys]] entry"
    );

    // `platform_operator = false` still counts as declared: it says something,
    // which is all this scan is about. Whether it says something USEFUL is
    // `Config::api_keys_that_authorize_nothing`'s question, not this one.
    let explicit_false = r#"\n[[api_keys]]\nid = \"k\"\nkey = \"s\"\nplatform_operator = false\n"#;
    assert_eq!(
        explicit_false.lines().count(),
        1,
        "the fixture must be one physical line carrying literal escapes; real newlines would \
         bypass logical_lines and make this control vacuous"
    );
    let escaped = scan(explicit_false);
    assert_eq!(
        escaped.len(),
        1,
        "and the escaped one-line spelling of a TOML block is read as the block it means"
    );
    assert_eq!(escaped[0].id, "k", "the escaped quote is unescaped too");
    assert!(
        escaped[0].declares_identity,
        "platform_operator=false still declares the key's posture"
    );
}

/// The marker is what keeps the guard usable, so it has to work in both
/// directions -- and only for the block it belongs to.
///
/// Mutations this catches: make [`is_marked_deliberate`] return `true`
/// unconditionally and the second assertion reds; drop the `.max(previous_end)`
/// clip and the third reds (a marker inside one fixture exempts the next one);
/// widen `to` from the block's own end to `first + MARKER_LOOKBEHIND_LINES` and
/// the fourth reds, which is the far one -- a single marker near the top of a
/// 4,000-line test file must not silence every fixture below it.
#[test]
fn the_deliberate_marker_exempts_its_own_block_and_not_its_neighbours() {
    let marked = format!(
        "\n# {DELIBERATE_MARKER}: proves the refusal fires\n{}",
        block("deliberate")
    );
    let findings = scan(&marked);
    assert_eq!(findings.len(), 1, "the scan still SEES it: {findings:?}");
    assert!(
        is_marked_deliberate(&marked, &findings, 0),
        "and the marker above it exempts it"
    );

    let unmarked = block("accidental");
    let findings = scan(&unmarked);
    assert_eq!(findings.len(), 1);
    assert!(
        !is_marked_deliberate(&unmarked, &findings, 0),
        "a block with no marker anywhere is a violation"
    );

    // Adjacent blocks: the second starts three lines after the first's marker,
    // well inside the lookbehind window. This is the shape the review found
    // live in `config/tests.rs`, where deleting a fixture's own marker left it
    // exempt via a neighbour's 13 lines up.
    let adjacent = format!(
        "\n# {DELIBERATE_MARKER}: for the block right here\n{}\n{}",
        block("deliberate"),
        block("accidental")
    );
    let findings = scan(&adjacent);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(is_marked_deliberate(&adjacent, &findings, 0));
    assert!(
        !is_marked_deliberate(&adjacent, &findings, 1),
        "one block's marker must not license the block right below it"
    );

    let far_apart = format!(
        "# {DELIBERATE_MARKER}: for the block right here\n{}{}\n{}",
        block("deliberate"),
        "# filler\n".repeat(MARKER_LOOKBEHIND_LINES + 5),
        block("accidental")
    );
    let findings = scan(&far_apart);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(is_marked_deliberate(&far_apart, &findings, 0));
    assert!(
        !is_marked_deliberate(&far_apart, &findings, 1),
        "one marker must not license every undeclared block in the rest of the file"
    );
}

/// One undeclared TOML block, built rather than spelled out.
///
/// The marker test needs fixtures that carry NO marker in their text, which is
/// impossible to write as a literal here: the repository walk reads this file
/// too, and a literal block with no marker beside it is a violation of the very
/// guard this file is. Building them from one marked template keeps the
/// fixtures honest in both directions.
///
/// #540-undeclared-on-purpose: the template below is the input to the detector,
/// not a key any loader will ever see.
fn block(id: &str) -> String {
    format!("[[api_keys]]\nid = \"{id}\"\nkey = \"s\"\n")
}

/// Every exemption is still needed, and excuses exactly as many blocks as it
/// says. An entry whose block has been fixed (or deleted) is a claim about the
/// tree that has quietly become false, and a stale exemption is how a list like
/// this stops meaning anything.
///
/// The count half is review minor 5: an entry is matched on `(path, id)`, so
/// without it one entry silently covers however many blocks in that file happen
/// to share the id.
#[test]
fn no_exemption_outlives_the_block_it_excuses() {
    let root = repo_root();
    let mut stale = Vec::new();
    for (path, id, count, _, _) in UNMARKED_EXEMPTIONS {
        let full = root.join(path);
        let Ok(source) = std::fs::read_to_string(&full) else {
            stale.push(format!("{path}: file no longer exists"));
            continue;
        };
        let found = undeclared(&source)
            .iter()
            .filter(|declaration| declaration.id == *id)
            .count();
        if found == 0 {
            stale.push(format!(
                "{path}: `{id}` is no longer an undeclared api key -- delete the exemption"
            ));
        } else if found != *count {
            stale.push(format!(
                "{path}: `{id}` matches {found} undeclared blocks but the exemption claims \
                 {count} -- update the count, or declare the new one"
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "stale entries in UNMARKED_EXEMPTIONS:\n{}",
        stale.join("\n")
    );
}

/// The debt list may shrink and never grow.
///
/// `Debt` entries are live defects -- fixtures that SHOULD declare an identity
/// and do not -- parked in a test that passes. Review minor 7's point is that a
/// list like that, with no ceiling, is where findings go to be forgotten. The
/// ceiling is the count at the time it was written, so the next agent who adds
/// one has to move this number and say why in a commit message.
#[test]
fn debt_is_not_growing() {
    let debt = UNMARKED_EXEMPTIONS
        .iter()
        .filter(|(_, _, _, kind, _)| *kind == Exemption::Debt)
        .count();
    assert!(
        debt <= MAX_KNOWN_UNDECLARED_DEBT,
        "{debt} exemptions are marked Debt, above the cap of {MAX_KNOWN_UNDECLARED_DEBT}. These \
         are fixtures that should declare a tenant identity and do not; the list exists to \
         shrink. Fix one before adding one."
    );
}
