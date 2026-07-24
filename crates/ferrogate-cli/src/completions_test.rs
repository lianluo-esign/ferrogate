// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Completion-generation snapshots (issue #365): every supported shell renders
//! a non-empty script from the full assembled command WITHOUT panicking, and
//! the script mentions the generic `ctl` resource families so completions are
//! proven to cover the metadata-driven subtree, not just the derived commands.

use super::*;
use clap::ValueEnum;

/// Generate the completion script for `shell` into a byte buffer.
fn render(shell: Shell) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    write_completions(shell, &mut buffer);
    String::from_utf8(buffer).expect("completion scripts are valid UTF-8")
}

/// Every `clap_complete::Shell` variant — the full supported set (bash, zsh,
/// fish, powershell, elvish) — generates a non-empty script and does not panic.
/// Iterating `value_variants()` means a future clap_complete adding a shell is
/// covered automatically.
#[test]
fn every_supported_shell_generates_non_empty_script() {
    for shell in Shell::value_variants() {
        let script = render(*shell);
        assert!(
            !script.trim().is_empty(),
            "completion script for {shell} must not be empty"
        );
        assert!(
            script.contains(BIN_NAME),
            "completion script for {shell} must reference the binary name"
        );
    }
}

/// The four shells the issue names explicitly are present in the supported set.
#[test]
fn required_shells_are_supported() {
    let names: Vec<String> = Shell::value_variants()
        .iter()
        .map(|shell| shell.to_string())
        .collect();
    for required in ["bash", "zsh", "fish", "powershell"] {
        assert!(
            names.iter().any(|name| name == required),
            "shell '{required}' must be a supported completion target; got {names:?}"
        );
    }
}

/// Completions are generated from the AUGMENTED command, so the generic `ctl`
/// resource-family namespace (#361–#365) and a representative resource group
/// appear in the script. This is the load-bearing guarantee that completions
/// cover the metadata-driven tree and not merely the derived `Cli`.
#[test]
fn bash_completions_cover_the_ctl_resource_tree() {
    let script = render(Shell::Bash);
    assert!(
        script.contains("ctl"),
        "bash completions must cover the generic `ctl` resource namespace"
    );
    assert!(
        script.contains("tenants"),
        "bash completions must cover a registered resource family (tenants)"
    );
}
