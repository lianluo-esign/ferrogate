// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Operator-intent confirmation for guarded Control Plane mutations.

use std::io::{self, IsTerminal, Write};

use ferrogate_control_plane_client::command::VerbDescriptor;
use ferrogate_control_plane_client::error::{CliError, CliResult};

/// Enforce the confirmation policy declared by a verb before any request body
/// or credential is read from stdin and before a transport can be constructed.
pub(crate) fn require(
    descriptor: &VerbDescriptor,
    group_name: &str,
    verb_name: &str,
    segments: &[String],
    dry_run: bool,
    confirmed: bool,
    non_interactive: bool,
) -> CliResult<()> {
    if !descriptor.requires_confirmation() || dry_run || confirmed {
        return Ok(());
    }

    let command = display_command(group_name, verb_name, segments);
    if non_interactive {
        return Err(CliError::usage(format!(
            "'{command}' requires confirmation; rerun with --yes because --non-interactive \
             disables prompts"
        )));
    }

    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(CliError::usage(format!(
            "'{command}' requires confirmation, but stdin is not a terminal; rerun with --yes \
             to acknowledge the operation explicitly"
        )));
    }

    eprint!("Confirm state-changing operation '{command}'? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| CliError::transport(format!("failed to display confirmation: {error}")))?;

    let mut answer = String::new();
    stdin
        .read_line(&mut answer)
        .map_err(|error| CliError::transport(format!("failed to read confirmation: {error}")))?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }

    Err(CliError::usage(format!(
        "'{command}' cancelled before any request was sent"
    )))
}

fn display_command(group_name: &str, verb_name: &str, segments: &[String]) -> String {
    let mut command = format!("ferrogate ctl {group_name} {verb_name}");
    for segment in segments {
        command.push(' ');
        command.push_str(segment);
    }
    command
}
