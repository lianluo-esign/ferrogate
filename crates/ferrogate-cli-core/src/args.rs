// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Clap-derived global flags (issue #360).
//!
//! These are the flags every command shares. They parse with Clap (the
//! workspace CLI parser, reused rather than a second arg framework) and fold
//! into the framework-agnostic [`GlobalOverrides`] the resolver consumes, so
//! precedence logic in [`crate::context`] stays independent of Clap and fully
//! unit-testable. Credential *material* is never a flag: `--token-env` names an
//! environment variable and `--token-stdin` reads the pipe, keeping secrets off
//! the process argument list where `ps` could read them.

use clap::Args;

use crate::auth::AuthSource;
use crate::context::GlobalOverrides;
use crate::error::CliResult;
use crate::output::OutputFormat;

/// Global flags available on every subcommand.
#[derive(Debug, Clone, Default, Args)]
pub struct GlobalArgs {
    /// Use a specific named context instead of the current one.
    #[arg(long, global = true)]
    pub context: Option<String>,

    /// Override the Control Plane API endpoint URL.
    #[arg(long, global = true)]
    pub endpoint: Option<String>,

    /// Override the tenant for this invocation. NOT HONORED BY THE SERVER
    /// TODAY: it becomes an `x-ferrogate-tenant` request header, which no
    /// Control Plane API operation declares — admin requests are scoped by the
    /// bearer token, so this neither narrows nor redirects the result; a note
    /// is printed to stderr on every use. Where an operation does accept tenant
    /// selection it is a `tenant` query parameter: pass `--filter tenant=<id>`.
    // The help must stay ONE doc-comment paragraph: clap's derive splits on the
    // first blank line and keeps only the leading paragraph as the short help
    // that `docs/cli-reference.md` is generated from, so a caveat below a blank
    // line would be true in the source and invisible in the reference.
    #[arg(long, global = true)]
    pub tenant: Option<String>,

    /// Read the bearer token from this environment variable.
    #[arg(long, global = true, value_name = "VAR")]
    pub token_env: Option<String>,

    /// Read the bearer token from stdin.
    #[arg(long, global = true, conflicts_with = "token_env")]
    pub token_stdin: bool,

    /// Per-request timeout in milliseconds.
    #[arg(long, global = true, value_name = "MILLIS")]
    pub timeout_millis: Option<u64>,

    /// Output format: table or json.
    #[arg(long, global = true, value_name = "FORMAT")]
    pub output: Option<String>,

    /// Do not prompt; fail instead of asking (for scripts/CI).
    #[arg(long, global = true)]
    pub non_interactive: bool,
}

impl GlobalArgs {
    /// Fold the parsed flags into framework-neutral [`GlobalOverrides`].
    ///
    /// The credential flags collapse to a single [`AuthSource`] override:
    /// `--token-stdin` wins if both are somehow present (they are declared
    /// mutually exclusive to Clap, but the collapse is explicit so behavior is
    /// obvious without trusting the arg parser). `--output` is validated here
    /// so an unknown format is a usage error at parse time, not later.
    pub fn to_overrides(&self) -> CliResult<GlobalOverrides> {
        let auth = if self.token_stdin {
            Some(AuthSource::Stdin)
        } else {
            self.token_env
                .as_ref()
                .map(|var| AuthSource::Env { var: var.clone() })
        };
        let output = match &self.output {
            Some(value) => Some(OutputFormat::parse(value)?),
            None => None,
        };
        Ok(GlobalOverrides {
            context: self.context.clone(),
            endpoint: self.endpoint.clone(),
            tenant: self.tenant.clone(),
            auth,
            timeout_millis: self.timeout_millis,
            output,
            non_interactive: self.non_interactive,
        })
    }
}

#[cfg(test)]
#[path = "args_test.rs"]
mod args_test;
