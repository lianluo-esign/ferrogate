// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Single source of truth for the full `ferrogate` command surface (issue
//! #365).
//!
//! The shipped binary parses the derived [`Cli`](crate::cli::Cli) tree
//! *augmented* with the generic Control Plane API resource families —
//! `ferrogate ctl <group> <verb>`, built from the `ferrogate-cli-core`
//! [`Registry`](ferrogate_cli_core::Registry) metadata (#361–#365). Shell
//! completions (`ferrogate completions`) and the generated command reference
//! (`docs/cli-reference.md`) must describe *exactly that* surface, or they
//! silently drift from what the binary accepts.
//!
//! Rather than re-assemble the command in three places (here, the completions
//! generator, the reference generator) and hope they stay identical, every
//! consumer builds it through [`assembled_command`]. `main` calls the same
//! helper so there is one — and only one — definition of the command the
//! product ships.

use clap::{Command, CommandFactory};

use crate::cli::Cli;

/// Build the resource-family registry the binary ships: every family the
/// `ferrogate-cli-core` library provides (#361–#365). Registration is a
/// compile-time-metadata operation that only fails on a duplicate group/verb —
/// a programming error — so it panics loudly rather than returning, exactly as
/// `main` does.
pub(crate) fn resource_registry() -> ferrogate_cli_core::Registry {
    let mut registry = ferrogate_cli_core::Registry::new();
    ferrogate_cli_core::register_resource_families(&mut registry)
        .expect("resource command families register cleanly");
    registry
}

/// Assemble the FULL `ferrogate` command: the derived `Cli` tree plus the
/// generic `ctl` resource-family subtree derived from `registry`. This is the
/// exact `clap::Command` `main` parses, so completions and the command
/// reference generated from it cover every shipped command including each
/// resource family.
pub(crate) fn assembled_command(registry: &ferrogate_cli_core::Registry) -> Command {
    Cli::command().subcommand(crate::ctl::build_ctl_command(registry))
}
