// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `ferrogate completions <shell>` — shell completion script generation (issue
//! #365).
//!
//! Completions are generated from [`command_tree::assembled_command`], the
//! SAME `clap::Command` the binary parses, so the emitted script covers the
//! full surface — the derived commands AND the generic `ctl <group> <verb>`
//! resource families (#361–#365). Generating from a freshly-derived `Cli`
//! alone would silently omit every `ctl` resource command.
//!
//! The script is written to stdout (the idiomatic `clap_complete` pattern), so
//! operators wire it into their shell however they prefer, e.g.:
//!
//! ```sh
//! ferrogate completions bash > /etc/bash_completion.d/ferrogate
//! ferrogate completions zsh  > "${fpath[1]}/_ferrogate"
//! ferrogate completions fish > ~/.config/fish/completions/ferrogate.fish
//! ```

use std::io::Write;

use clap_complete::{generate, Shell};

use crate::command_tree;

/// Binary name stamped into the generated completion script. Must match the
/// `[[bin]] name` so the script binds to the installed `ferrogate` executable.
const BIN_NAME: &str = "ferrogate";

/// Write a completion script for `shell` to `writer`, generated from the full
/// assembled command surface. Separated from the stdout entrypoint so tests can
/// capture the script into a buffer and assert it is non-empty for every shell.
pub(crate) fn write_completions<W: Write>(shell: Shell, writer: &mut W) {
    let registry = command_tree::resource_registry();
    let mut command = command_tree::assembled_command(&registry);
    generate(shell, &mut command, BIN_NAME, writer);
}

/// Execute `ferrogate completions <shell>`: emit the completion script to
/// stdout.
pub(crate) fn execute(shell: Shell) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    write_completions(shell, &mut stdout);
    Ok(())
}

#[cfg(test)]
#[path = "completions_test.rs"]
mod completions_test;
