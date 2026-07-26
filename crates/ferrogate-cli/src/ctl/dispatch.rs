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
use ferrogate_cli_core::resource::redact_secret_fields;

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
///
/// Callers that know which resource group they invoked should use
/// [`report_error_for`] so the error's structured `details` payload gets the
/// same secret redaction a success body gets.
pub(crate) fn report_error(error: &CliError) {
    report_error_for(error, &[]);
}

/// Render a client error, redacting `secret_fields` from the structured
/// `details` payload.
///
/// Why redaction belongs on the error path too: the transport's
/// `collect_extra_details` forwards **every** error-object key except
/// `message`/`type`/`code`/`request_id`, while a success body is filtered
/// through `redact_response`/`redact_secret_fields`. A server error that echoes
/// the offending request — a rejected virtual-key create carrying `key`, an
/// asset-transfer failure carrying `upload_url` — therefore reached stderr in
/// clear while the same field on the 200 path was blanked. Redaction that only
/// covers the happy path is not redaction.
pub(crate) fn report_error_for(error: &CliError, secret_fields: &[&str]) {
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
        // The structured payload is the actionable half of a validation or
        // conflict failure (`expected_version`, per-field violations, quota
        // headroom). Decoding it in the transport and then never showing it
        // would make the "preserve error details" contract a no-op.
        if let Some(details) = &api.details {
            eprintln!("  details: {}", render_details(details, secret_fields));
        }
    }
}

/// Render an error envelope's structured `details` payload for stderr with the
/// invoked group's one-time secret fields blanked. Pure, so the redaction is
/// unit-testable without capturing process stderr.
pub(crate) fn render_details(details: &serde_json::Value, secret_fields: &[&str]) -> String {
    let mut details = details.clone();
    if !secret_fields.is_empty() {
        redact_secret_fields(&mut details, secret_fields);
    }
    serde_json::to_string(&details)
        .unwrap_or_else(|error| format!("<unrenderable details: {error}>"))
}

#[cfg(test)]
#[path = "dispatch_test.rs"]
mod dispatch_test;
