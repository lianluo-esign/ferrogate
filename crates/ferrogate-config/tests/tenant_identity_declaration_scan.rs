// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Repository-wide guard that every declared API key in the tree states a tenant identity (#540), across all three dialects that spell one.

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
//! against whatever the repository happens to contain today. Three dialects:
//!
//! * **TOML** -- a `[[api_keys]]` table array. This is the dialect the original
//!   sweep walked, and scanning *every text file* rather than `**/*.toml` is
//!   the point: 282 of the ~291 blocks live inside Rust raw strings, so a
//!   `.toml`-only walk would report zero, vacuously.
//! * **Caddyfile** -- an `api_key <id> { ... }` block, wherever it appears,
//!   including inside a fenced code block in `README.md`. That is exactly where
//!   two of the four misses were, and a copied quickstart that refuses to start
//!   is the worst place to find out.
//! * **JSON** -- an object literal that names `"id"`, `"scopes"` and one of
//!   `"key"`/`"key_hash"`/`"key_env"`. This covers `serde_json::from_value`
//!   fixtures and `POST`/`PUT /admin/v1/api-keys` request bodies written as
//!   string literals, which is where the remaining two misses were.
//!
//! **Stated limits.** A key assembled at runtime from parts, or built as a Rust
//! struct literal with `..Default::default()`, is invisible to a text scan and
//! is not audited here; those are held by `Config::validate` and by
//! `Config::ensure_api_key_declares_tenant_identity` on the mint path, which
//! refuse them at the moment they are used. A *fourth* dialect arriving later
//! is likewise invisible -- this scan cannot know about a spelling that does
//! not exist yet. Both are written down rather than implied away.
//!
//! # Deliberately undeclared fixtures
//!
//! A test that proves the refusal fires needs a key that declares nothing. Such
//! a block says so, in a comment inside it or just above it, with the marker
//! [`DELIBERATE_MARKER`] -- so the exemption travels with the fixture instead of
//! living in a list that goes stale when the fixture moves. Blocks in files this
//! change could not edit (a parallel slice owns them, or the format has no
//! comments) are listed in [`UNMARKED_EXEMPTIONS`] with the reason, which is a
//! debt list and is meant to shrink.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The in-source opt-out. A block carrying this is a fixture whose whole
/// purpose is to be undeclared.
const DELIBERATE_MARKER: &str = "#540-undeclared-on-purpose";

/// How far above a block's first line the marker may sit, so a doc comment on
/// the test that owns the fixture can carry it.
const MARKER_LOOKBEHIND_LINES: usize = 20;

/// Undeclared blocks this change could not annotate, each with the reason.
///
/// `(repo-relative path, key id, reason)`. Matched on the pair, so the line
/// number may move freely. Every entry is either a deliberate negative fixture
/// in a file owned by a parallel slice this session, or a file whose format has
/// no comment syntax to carry the marker.
const UNMARKED_EXEMPTIONS: &[(&str, &str, &str)] = &[
    (
        "tests/fixtures/governed-decisions/auth__tenant-identity-required.json",
        "key-undeclared",
        "the conformance fixture FOR the tenant_identity_required refusal -- being undeclared is \
         its entire content, and JSON has no comment syntax to carry the marker",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "legacy-admin",
        "deliberate: a pre-#515 key under the `implicit_platform_operator = true` opt-in. Not \
         marked because a parallel slice (#548) owns crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "legacy",
        "deliberate: the `null` declaration half of the declared/effective pair. Not marked \
         because a parallel slice (#548) owns crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/tests/api_key_tenancy_admin_api.rs",
        "unscoped",
        "deliberate: the POST body #540 must answer 400 to. Not marked because a parallel slice \
         (#548) owns crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/tests/check_command.rs",
        "bootstrap",
        "deliberate: the config `ferrogate check` must refuse. Not marked because a parallel \
         slice (#548) owns crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "admin",
        "NOT deliberate, and reported rather than endorsed: an `ApiKey` fixture that never \
         reaches `Config::validate`, so nothing refuses it today. It should declare \
         `platform_operator`. A parallel slice (#548) owns crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "chat",
        "NOT deliberate, and reported rather than endorsed: a chat-only fixture that should name \
         a tenant (#563's argument). A parallel slice (#548) owns crates/ferrogate-cli/ this \
         session",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "off",
        "NOT deliberate; see the `admin` entry. A parallel slice (#548) owns \
         crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/src/admin_api_test.rs",
        "old",
        "NOT deliberate; see the `admin` entry. A parallel slice (#548) owns \
         crates/ferrogate-cli/ this session",
    ),
    (
        "crates/ferrogate-cli/tests/ai_proxy_runtime.rs",
        "client",
        "a PATCH body that omits organization_id after a create that declared it. It passes \
         today only because `apply_tenant_refs_to_api_keys` re-applies the binding from the \
         tenants documents -- a re-merge two layers below the request. A parallel slice (#548) \
         owns crates/ferrogate-cli/ this session",
    ),
    (
        "docs/openapi/admin-api.openapi.json",
        "key_dev",
        "the spec's example api-key payload, which an operator copies: it should declare an \
         identity. JSON has no comment syntax, and a parallel slice (#548) owns docs/openapi/ \
         this session",
    ),
    (
        "docs/openapi/admin-api.compatibility-baseline.json",
        "key_dev",
        "the frozen compatibility baseline of the above; it moves when the spec does",
    ),
];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dialect {
    Toml,
    Caddyfile,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    dialect: Dialect,
    id: String,
    /// 1-based line of the block's first line.
    line: usize,
}

/// Every api-key declaration in `source` that names neither `organization_id`
/// nor `platform_operator`, in any of the three dialects.
///
/// Pure: no filesystem, no exemptions. Exemptions are applied by the caller, so
/// the unit cases below can assert on detection without a marker silencing the
/// very thing they are testing.
fn scan(source: &str) -> Vec<Finding> {
    let mut findings = scan_toml(source);
    findings.extend(scan_caddyfile(source));
    findings.extend(scan_json(source));
    // Source order, so a caller can reason about "the first one" and so a
    // failure message reads top to bottom like the file it names.
    findings.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.dialect.cmp(&right.dialect))
            .then_with(|| left.id.cmp(&right.id))
    });
    findings
}

fn scan_toml(source: &str) -> Vec<Finding> {
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() != "[[api_keys]]" {
            index += 1;
            continue;
        }
        let start = index;
        let mut id = String::new();
        let mut declared = false;
        let mut cursor = index + 1;
        while cursor < lines.len() {
            let line = lines[cursor].trim();
            // The next table header ends the block; so does the end of the Rust
            // raw string the block is embedded in.
            if line.starts_with('[')
                || line.starts_with("\"#")
                || line.ends_with("\"#;")
                || line.ends_with("\"#,")
            {
                break;
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
        if !declared {
            findings.push(Finding {
                dialect: Dialect::Toml,
                id: if id.is_empty() {
                    "<unnamed>".to_string()
                } else {
                    id
                },
                line: start + 1,
            });
        }
        index = cursor;
    }
    findings
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

fn scan_caddyfile(source: &str) -> Vec<Finding> {
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(id) = caddyfile_block_id(lines[index]) else {
            index += 1;
            continue;
        };
        let start = index;
        let mut depth = 1usize;
        let mut declared = false;
        let mut cursor = index + 1;
        while cursor < lines.len() && depth > 0 {
            let line = lines[cursor];
            for character in line.chars() {
                match character {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            if depth > 0 {
                let first = line.split_whitespace().next().unwrap_or_default();
                if first == "organization_id" || first == "platform_operator" {
                    declared = true;
                }
            }
            cursor += 1;
        }
        if !declared {
            findings.push(Finding {
                dialect: Dialect::Caddyfile,
                id,
                line: start + 1,
            });
        }
        index = cursor.max(start + 1);
    }
    findings
}

/// `api_key <id> {` opens a key block. `api_key {env.OPENAI_API_KEY}` is the
/// *provider's* credential directive and is not one, which is why the name has
/// to be a real token rather than merely "something before the brace".
fn caddyfile_block_id(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("api_key ")?;
    let rest = rest.strip_suffix('{')?.trim();
    if rest.is_empty() || rest.starts_with('{') || rest.starts_with('"') {
        return None;
    }
    Some(rest.to_string())
}

fn scan_json(source: &str) -> Vec<Finding> {
    let bytes: Vec<char> = source.chars().collect();
    let mut findings = Vec::new();
    let mut open: Option<usize> = None;
    let mut line = 1usize;
    let mut open_line = 1usize;
    for (index, character) in bytes.iter().enumerate() {
        match character {
            '\n' => line += 1,
            '{' => {
                open = Some(index);
                open_line = line;
            }
            '}' => {
                // Innermost objects only: `open` is reset by every `{`, so it
                // holds the most recent one and this slice contains no nested
                // object. An api-key payload has arrays but no sub-objects.
                if let Some(start) = open.take() {
                    let object: String = bytes[start..=index].iter().collect();
                    if let Some(id) = json_api_key_id(&object) {
                        if !object.contains("\"organization_id\"")
                            && !object.contains("\"platform_operator\"")
                        {
                            findings.push(Finding {
                                dialect: Dialect::Json,
                                id,
                                line: open_line,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    findings
}

fn json_api_key_id(object: &str) -> Option<String> {
    if !object.contains("\"id\"") || !object.contains("\"scopes\"") {
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
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn is_marked_deliberate(source: &str, finding: &Finding) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let first = finding.line.saturating_sub(1);
    let from = first.saturating_sub(MARKER_LOOKBEHIND_LINES);
    // The block's own body is bounded by the next declaration at the earliest;
    // scanning to the end of the file would let one marker silence everything
    // after it, so the window stops at a fixed distance below the header too.
    let to = (first + MARKER_LOOKBEHIND_LINES).min(lines.len());
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

/// The guard. Every api-key declaration in the tree either states a tenant
/// identity, carries the deliberate marker, or is listed with a reason.
///
/// Mutation this catches: delete any `platform_operator = true` /
/// `organization_id = "..."` line from any fixture in the tree -- the four
/// fixtures the review found, the two READMEs, or any of the ~300 others -- and
/// this test names the file, the line, the dialect and the key id. It is
/// deliberately NOT satisfiable by the flip being reverted, because it never
/// reads `TenancyConfig`: it is a statement about the tree, not about the
/// default.
#[test]
fn every_api_key_declaration_in_the_tree_states_a_tenant_identity() {
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

    let exempt: BTreeSet<(&str, &str)> = UNMARKED_EXEMPTIONS
        .iter()
        .map(|(path, id, _)| (*path, *id))
        .collect();

    let mut violations = Vec::new();
    let mut declarations = 0usize;
    let mut scanned = 0usize;
    for path in &files {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue; // binary or unreadable: not a config dialect
        };
        scanned += 1;
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for finding in scan(&source) {
            declarations += 1;
            if is_marked_deliberate(&source, &finding) {
                continue;
            }
            if exempt.contains(&(relative.as_str(), finding.id.as_str())) {
                continue;
            }
            violations.push(format!(
                "{relative}:{} [{:?}] api key `{}` declares neither organization_id nor \
                 platform_operator",
                finding.line, finding.dialect, finding.id
            ));
        }
    }

    assert!(
        scanned > 500,
        "only {scanned} text files were read; the scan must actually read the tree"
    );
    assert!(
        violations.is_empty(),
        "#540: an API key that declares neither organization_id nor platform_operator is refused \
         at load and refused at authentication, so a fixture or example in this shape is a test \
         that cannot run and a quickstart that cannot start. Declare each one \
         (`platform_operator = true` / `platform_operator on` for a key that administers every \
         tenant, `organization_id` for a key that belongs to one), or -- if being undeclared IS \
         what the fixture is for -- put `{DELIBERATE_MARKER}` in a comment inside it or just \
         above it.\n\n{}\n\n({declarations} undeclared-or-exempt declarations seen across \
         {scanned} text files)",
        violations.join("\n")
    );
}

/// The scan itself, against synthetic sources, so its reach is a claim that can
/// be checked rather than a property of whatever the tree contains today.
///
/// Mutation this catches: narrow [`scan_toml`]'s walk to `.toml` files, or drop
/// either of the other two dialects, and the corresponding case reds. Before
/// this file existed, a `**/*.toml`-only verifier would have reported `0
/// undeclared` on a tree with 282 blocks it could not see.
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

[[api_keys]]
id = "declared-toml"
name = "Declared"
key = "secret"
organization_id = "tenant-a"
"#.to_string()
}
"##;
    let toml_findings = scan(rust_raw_string);
    assert_eq!(
        toml_findings.len(),
        1,
        "exactly the undeclared block: {toml_findings:?}"
    );
    assert_eq!(toml_findings[0].dialect, Dialect::Toml);
    assert_eq!(toml_findings[0].id, "undeclared-toml");

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
        api_key declared_caddy {
            key other-secret
            scopes admin.read
            platform_operator on
        }
    }
}
```
"#;
    let caddy_findings = scan(markdown);
    assert_eq!(
        caddy_findings.len(),
        1,
        "the provider credential directive is not a key block: {caddy_findings:?}"
    );
    assert_eq!(caddy_findings[0].dialect, Dialect::Caddyfile);
    assert_eq!(caddy_findings[0].id, "undeclared_caddy");

    // A JSON request body / `serde_json::from_value` fixture.
    let json_bodies = r#"
    // #540-undeclared-on-purpose: the input the scan must detect
    let created = post("/admin/v1/api-keys",
        r#_{"id":"undeclared-json","name":"C","key":"s","scopes":["chat.completions"]}_#);
    let scoped = post("/admin/v1/api-keys",
        r#_{"id":"declared-json","name":"D","key":"s","scopes":["chat.completions"],"organization_id":"tenant-a"}_#);
    let unrelated = json!({"id":"m1","object":"model","owned_by":"ferrogate"});
"#;
    let json_findings = scan(json_bodies);
    assert_eq!(
        json_findings.len(),
        1,
        "an object without \"scopes\" and a key field is not an api key: {json_findings:?}"
    );
    assert_eq!(json_findings[0].dialect, Dialect::Json);
    assert_eq!(json_findings[0].id, "undeclared-json");

    // `platform_operator = false` still counts as declared: it says something,
    // which is all this scan is about. Whether it says something USEFUL is
    // `Config::api_keys_that_authorize_nothing`'s question, not this one.
    let explicit_false = "\n[[api_keys]]\nid = \"k\"\nkey = \"s\"\nplatform_operator = false\n";
    assert!(scan(explicit_false).is_empty());
}

/// The marker is what keeps the guard usable, so it has to work in both
/// directions.
///
/// Mutation this catches: make [`is_marked_deliberate`] return `true`
/// unconditionally and the second assertion reds; make it scan the whole file
/// and the third reds, which is the one that matters -- a single marker near
/// the top of a 4,000-line test file must not silence every fixture below it.
#[test]
fn the_deliberate_marker_exempts_its_own_block_and_not_the_whole_file() {
    let marked = "\n# #540-undeclared-on-purpose: proves the refusal fires\n[[api_keys]]\nid = \
                  \"deliberate\"\nkey = \"s\"\n";
    let findings = scan(marked);
    assert_eq!(findings.len(), 1, "the scan still SEES it: {findings:?}");
    assert!(
        is_marked_deliberate(marked, &findings[0]),
        "and the marker above it exempts it"
    );

    let unmarked = "\n[[api_keys]]\nid = \"accidental\"\nkey = \"s\"\n";
    let findings = scan(unmarked);
    assert_eq!(findings.len(), 1);
    assert!(
        !is_marked_deliberate(unmarked, &findings[0]),
        "a block with no marker anywhere is a violation"
    );

    let far_apart = format!(
        "# #540-undeclared-on-purpose: for the block right here\n[[api_keys]]\nid = \
         \"deliberate\"\nkey = \"s\"\n{}\n[[api_keys]]\nid = \"accidental\"\nkey = \"s\"\n",
        "# filler\n".repeat(MARKER_LOOKBEHIND_LINES + 5)
    );
    let findings = scan(&far_apart);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(is_marked_deliberate(&far_apart, &findings[0]));
    assert!(
        !is_marked_deliberate(&far_apart, &findings[1]),
        "one marker must not license every undeclared block in the rest of the file"
    );
}

/// Every exemption is still needed. An entry whose block has been fixed (or
/// deleted) is a claim about the tree that has quietly become false, and a
/// stale exemption is how a list like this stops meaning anything.
#[test]
fn no_exemption_outlives_the_block_it_excuses() {
    let root = repo_root();
    let mut stale = Vec::new();
    for (path, id, _) in UNMARKED_EXEMPTIONS {
        let full = root.join(path);
        let Ok(source) = std::fs::read_to_string(&full) else {
            stale.push(format!("{path}: file no longer exists"));
            continue;
        };
        if !scan(&source).iter().any(|finding| finding.id == *id) {
            stale.push(format!(
                "{path}: `{id}` is no longer an undeclared api key -- delete the exemption"
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "stale entries in UNMARKED_EXEMPTIONS:\n{}",
        stale.join("\n")
    );
}
