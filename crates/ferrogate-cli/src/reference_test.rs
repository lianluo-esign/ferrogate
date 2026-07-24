// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Reference-snapshot + help-stability tests (issue #365).
//!
//! * The committed `docs/cli-reference.md` must equal the freshly-generated
//!   reference — the "reference snapshot" acceptance. On drift the test fails
//!   with the exact regenerate command (and regenerates in place when
//!   `FERROGATE_REGENERATE_DOCS` is set).
//! * The top-level `--help`, `ctl --help`, and a representative family
//!   `--help` render stably (asserted via load-bearing structural markers that
//!   are robust to clap's terminal-width/version formatting).

use std::path::PathBuf;

use crate::command_tree;

/// Absolute path to the committed reference doc, resolved from this crate's
/// manifest dir so the test is CWD-independent (cargo runs it from the crate
/// root, but the doc lives at the workspace root).
fn reference_doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("cli-reference.md")
}

/// Render the long `--help` for a (possibly nested) command path against the
/// full assembled tree, e.g. `["ctl", "tenants"]`.
fn render_help(path: &[&str]) -> String {
    let registry = command_tree::resource_registry();
    let mut command = command_tree::assembled_command(&registry);
    for segment in path {
        command = command
            .find_subcommand(segment)
            .unwrap_or_else(|| panic!("subcommand '{segment}' must exist in the assembled tree"))
            .clone();
    }
    command.render_long_help().to_string()
}

/// The committed reference is byte-identical to the generated one. Set
/// `FERROGATE_REGENERATE_DOCS=1` to rewrite it in place instead of asserting.
#[test]
fn reference_doc_is_in_sync() {
    let generated = super::render_reference();
    let path = reference_doc_path();

    if std::env::var_os("FERROGATE_REGENERATE_DOCS").is_some() {
        std::fs::write(&path, &generated).expect("write regenerated cli-reference.md");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}. Generate it with \
             `FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli reference`",
            path.display()
        )
    });

    assert_eq!(
        committed, generated,
        "docs/cli-reference.md is out of sync with the command tree. Regenerate with \
         `FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli reference`"
    );
}

/// The generated reference actually reaches the generic resource families, so
/// the doc is proven to describe the augmented tree — not just the derived
/// `Cli`.
#[test]
fn reference_covers_augmented_surface() {
    let generated = super::render_reference();
    for marker in [
        "## `ferrogate`",
        "`ferrogate completions",
        "`ferrogate ctl`",
        "`ferrogate ctl tenants list`",
        "`ferrogate control-api serve`",
        "`ferrogate admin-api serve`",
    ] {
        assert!(
            generated.contains(marker),
            "generated reference must contain marker: {marker}"
        );
    }
}

/// Top-level `--help` renders stably: it lists the derived commands, the new
/// `completions` command, and the generic `ctl` namespace.
#[test]
fn top_level_help_renders_stably() {
    let help = render_help(&[]);
    for marker in [
        "completions",
        "ctl",
        "control-api",
        "admin-api",
        "context",
        "ops",
    ] {
        assert!(
            help.contains(marker),
            "top-level --help must mention '{marker}'.\n---\n{help}"
        );
    }
}

/// `ctl --help` renders stably: it lists a stable sample of registered resource
/// families sourced from the registry metadata.
#[test]
fn ctl_help_lists_resource_families() {
    let help = render_help(&["ctl"]);
    for family in ["tenants", "assets", "plans", "wallets"] {
        assert!(
            help.contains(family),
            "`ctl --help` must list resource family '{family}'.\n---\n{help}"
        );
    }
}

/// A representative family `--help` (`ctl tenant-accounts --help`) renders
/// stably: it lists the family's verbs.
#[test]
fn family_help_renders_stably() {
    let help = render_help(&["ctl", "tenant-accounts"]);
    for verb in ["list", "get", "create"] {
        assert!(
            help.contains(verb),
            "`ctl tenant-accounts --help` must list verb '{verb}'.\n---\n{help}"
        );
    }
}
