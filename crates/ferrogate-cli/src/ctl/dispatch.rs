// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Shared dispatch glue between the `ferrogate` binary and the
//! `ferrogate-cli-core` foundation (issue #360).
//!
//! This is the seam that turns parsed Clap flags plus process state (env,
//! stdin, the on-disk store) into the fully resolved [`EffectiveContext`] the
//! transport consumes, and that maps a [`CliError`] onto stderr diagnostics.
//! Keeping it here means both the `context` and `ops` command modules — and
//! every later resource family — share one precedence path and one diagnostic
//! format instead of re-deriving them.

use std::io::Read;

use ferrogate_cli_core::args::GlobalArgs;
use ferrogate_cli_core::auth::SecretResolver;
use ferrogate_cli_core::context::{self, EffectiveContext, EnvOverrides};
use ferrogate_cli_core::error::{CliError, CliResult};

use super::store;

/// Reads secrets from the real process environment and stdin. The foundation's
/// resolver is a trait precisely so this side-effecting implementation lives in
/// the binary while `ferrogate-cli-core`'s own tests stay hermetic.
pub(crate) struct ProcessSecretResolver;

impl SecretResolver for ProcessSecretResolver {
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn read_stdin(&self) -> CliResult<String> {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| {
                CliError::auth(format!("failed to read the token from stdin: {error}"))
            })?;
        Ok(buffer)
    }
}

/// Apply the foundation's precedence rule (flag > env > context > default) using
/// the real process environment and the on-disk store. Commands read the
/// returned [`EffectiveContext`] and never re-derive precedence themselves.
pub(crate) fn resolve_effective(global: &GlobalArgs) -> CliResult<EffectiveContext> {
    let overrides = global.to_overrides()?;
    let env = EnvOverrides::from_lookup(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })?;
    let store = store::load()?;
    context::resolve(&store, &env, &overrides)
}

/// Build the small current-thread async runtime used to drive one blocking CLI
/// invocation of the async transport. `ferrogate`'s `main` is a synchronous
/// entrypoint, so each remote command spins up a runtime, runs one request to
/// completion, and tears it down.
pub(crate) fn runtime() -> CliResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::transport(format!("failed to start the async runtime: {error}")))
}

/// Render a client error to stderr (never stdout — stdout is data only),
/// preserving the server's error code, request id, and retry hint when the
/// failure carried an API error envelope.
pub(crate) fn report_error(error: &CliError) {
    eprintln!("error: {error}");
    if let CliError::Api(api) = error {
        eprintln!("  code: {}", api.code);
        eprintln!("  http-status: {}", api.http_status);
        if let Some(request_id) = &api.request_id {
            eprintln!("  request-id: {request_id}");
        }
        if let Some(trace_id) = &api.trace_id {
            eprintln!("  trace-id: {trace_id}");
        }
        if let Some(retry_after) = api.retry_after_secs {
            eprintln!("  retry-after: {retry_after}s");
        }
    }
}
