// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `ferrogate ops status` — the first user-reachable vertical slice on the
//! shared Control Plane API client (issue #360).
//!
//! This wires the whole foundation stack together for exactly one operation
//! (`GET /admin/v1/status`), proving the pattern later resource families reuse:
//!
//! 1. resolve precedence into an [`EffectiveContext`] ([`super::dispatch`]);
//! 2. resolve the credential source into an optional bearer credential;
//! 3. build the request from the shared `ops` metadata via the declarative
//!    [`ResourceApi`](ferrogate_cli_core::resource::ResourceApi) builder — no
//!    hand-rolled URL;
//! 4. execute it through the typed [`ControlPlaneClient`] over the workspace
//!    async HTTP/TLS stack ([`ReqwestTransport`]);
//! 5. fail closed on an incompatible server contract before rendering;
//! 6. render data to stdout (table or stable JSON) and diagnostics to stderr;
//! 7. map any failure onto a stable [`ExitClass`](ferrogate_cli_core::ExitClass).

use ferrogate_cli_core::action_identity::{ClientActionIdentity, FingerprintEnv};
use ferrogate_cli_core::auth::{resolve_credential, Credential};
use ferrogate_cli_core::context::EffectiveContext;
use ferrogate_cli_core::error::CliResult;
use ferrogate_cli_core::output::{render_json, OutputFormat, Table};
use ferrogate_cli_core::registry_helpers::ResourceInput;
use ferrogate_cli_core::transport::{ApiResponse, ControlPlaneClient, ReqwestTransport};
use ferrogate_cli_core::{ops, version};
use serde_json::Value;

use crate::cli::{OpsArgs, OpsCommands};

use super::dispatch::{self, report_error, ProcessSecretResolver};

/// Dispatch an `ops` verb and translate the result into a process exit code.
pub(crate) fn run_ops(args: OpsArgs) -> i32 {
    match execute(args) {
        Ok(()) => 0,
        Err(error) => {
            report_error(&error);
            error.exit_class().code()
        }
    }
}

fn execute(args: OpsArgs) -> CliResult<()> {
    let effective = dispatch::resolve_effective(&args.global)?;
    let credential = resolve_credential(&effective.auth, &ProcessSecretResolver)?;
    match args.command {
        OpsCommands::Status => status(effective, credential),
    }
}

fn status(effective: EffectiveContext, credential: Option<Credential>) -> CliResult<()> {
    // Build the request from shared compile-time metadata rather than a literal
    // path, so this slice cannot drift from the `ops` family's declared surface.
    let spec = ops::build_system("status", &ResourceInput::new())?;
    let output_format = effective.output;

    // One identity per operator action (issue #548). `ops status` is a read,
    // and a read is also "what this CLI did", so it carries the same attribution
    // a mutation does.
    let identity = ClientActionIdentity::mint(&effective, &FingerprintEnv::from_process())?;
    let runtime = dispatch::runtime()?;
    let response: ApiResponse = runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport, identity);
        client.send(&spec).await
    })?;

    // Fail closed on an unsupported server contract instead of mis-rendering a
    // status shaped by an older API version.
    if let Some(server_version) = response.body.get("version").and_then(Value::as_str) {
        version::check_compatibility(server_version)?;
    }

    // Diagnostics (correlation ids) → stderr; the payload stays clean on stdout
    // so `--output json` is pipe-safe.
    if let Some(request_id) = &response.request_id {
        eprintln!("request-id: {request_id}");
    }
    if let Some(trace_id) = &response.trace_id {
        eprintln!("trace-id: {trace_id}");
    }

    match output_format {
        OutputFormat::Json => println!("{}", render_json(&response.body)?),
        OutputFormat::Table => println!("{}", status_table(&response.body)?.render()),
    }
    Ok(())
}

/// Project the `/admin/v1/status` document into a stable, human-readable
/// two-column table. Pure so it is unit-testable without a live server. Missing
/// fields render as `-` rather than failing, keeping the CLI forward-compatible
/// with a server that omits an optional field.
fn status_table(body: &Value) -> CliResult<Table> {
    let scalar = |key: &str| -> String {
        body.get(key)
            .map(render_scalar)
            .unwrap_or_else(|| "-".to_string())
    };
    let rows = vec![
        vec!["service".to_string(), scalar("service")],
        vec!["version".to_string(), scalar("version")],
        vec!["runtime".to_string(), scalar("runtime")],
        vec!["snapshot".to_string(), scalar("snapshot")],
        vec![
            "providers (enabled/total)".to_string(),
            enabled_of_total(body, "enabled_providers", "providers"),
        ],
        vec![
            "models (enabled/total)".to_string(),
            enabled_of_total(body, "enabled_models", "models"),
        ],
        vec![
            "routes (enabled/total)".to_string(),
            enabled_of_total(body, "enabled_routes", "routes"),
        ],
        vec![
            "upstreams (enabled/total)".to_string(),
            enabled_of_total(body, "enabled_upstreams", "upstreams"),
        ],
        vec!["api_keys".to_string(), scalar("api_keys")],
        vec!["tools".to_string(), scalar("tools")],
        vec!["auth_required".to_string(), scalar("auth_required")],
    ];
    Table::new(vec!["FIELD".to_string(), "VALUE".to_string()], rows)
}

/// Render a JSON scalar without the surrounding quotes a raw `to_string` would
/// add; fall back to compact JSON for a non-scalar value.
fn render_scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_string(),
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        other => other.to_string(),
    }
}

/// Format an `enabled/total` pair, or `-` when neither count is present.
fn enabled_of_total(body: &Value, enabled_key: &str, total_key: &str) -> String {
    let enabled = body.get(enabled_key).and_then(Value::as_u64);
    let total = body.get(total_key).and_then(Value::as_u64);
    match (enabled, total) {
        (Some(enabled), Some(total)) => format!("{enabled}/{total}"),
        (None, Some(total)) => format!("-/{total}"),
        (Some(enabled), None) => format!("{enabled}/-"),
        (None, None) => "-".to_string(),
    }
}

#[cfg(test)]
#[path = "ops_cmd_test.rs"]
mod ops_cmd_test;
