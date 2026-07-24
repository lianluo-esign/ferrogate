// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Generic Control Plane API resource commands wired into the `ferrogate`
//! binary (issues #361–#365 on the #360 foundation).
//!
//! #360 wired two hand-written verticals (`ops status`, `context`). The
//! resource command families — organization/IAM (#361), agent/worker/MCP/
//! tool-approval/guardrail (#362), asset/transfer/channel/static-site (#363),
//! and billing/usage/evidence/operator-action (#364) — are fully implemented in
//! `ferrogate-cli-core` and registered onto a
//! [`Registry`](ferrogate_cli_core::command::Registry), but nothing exposed them
//! to an operator. This module is that exposure, and it is deliberately
//! **generic**: the whole `ferrogate ctl <group> <verb>` command tree is built
//! from the registry's compile-time metadata
//! ([`GroupDescriptor`](ferrogate_cli_core::command::GroupDescriptor) /
//! [`VerbDescriptor`](ferrogate_cli_core::command::VerbDescriptor)), and every
//! matched command is routed through the shared
//! [`build_request`](ferrogate_cli_core::dispatch::build_request) seam. Adding a
//! resource family in `ferrogate-cli-core` therefore requires **no change here**
//! — the new group appears in the tree and dispatches on its own.
//!
//! The families are namespaced under `ctl` (rather than mounted at the binary
//! root) so their nouns cannot collide with the pre-existing top-level
//! `ferrogate assets` / `ferrogate plans` gateway commands, which are preserved
//! unchanged alongside #360's `ops` / `context`.
//!
//! Every verb reuses #360's foundation end to end: the shared transport, the
//! flag>env>context>default precedence, table/JSON rendering, the stable
//! error→exit-class mapping, and — for read verbs — secret redaction of any
//! one-time key material a server echoes back.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{ArgMatches, Args, Command, FromArgMatches};
use ferrogate_cli_core::args::GlobalArgs;
use ferrogate_cli_core::auth::resolve_credential;
use ferrogate_cli_core::command::Registry;
use ferrogate_cli_core::dispatch::{build_request, redact_response};
use ferrogate_cli_core::error::{CliError, CliResult};
use ferrogate_cli_core::output::{render_json, OutputFormat, Table};
use ferrogate_cli_core::registry_helpers::ResourceInput;
use ferrogate_cli_core::resource::ListParams;
use ferrogate_cli_core::transport::{
    ApiResponse, ControlPlaneClient, PageRequest, ReqwestTransport,
};
use serde_json::{Map, Value};

use super::dispatch::{self, report_error, ProcessSecretResolver};

/// Top-level namespace command that hosts every registered resource family.
pub(crate) const CTL_COMMAND: &str = "ctl";

/// Resource-specific arguments shared by every generic verb: the id path
/// segments, an optional JSON request document (for writes), and list
/// pagination/filters. Reused verbatim across all verbs, so the request shape a
/// verb needs is validated by the shared `ferrogate-cli-core` builders (which
/// error when a required id or body is missing) rather than re-declared per
/// resource — the point of the generic wiring.
#[derive(Debug, Args)]
struct ResourceArgs {
    /// Resource id path segment(s) — e.g. a single id, or a `scope_type`
    /// `scope_id` pair for composite keys. Omitted for collection verbs
    /// (`list`/`create`).
    #[arg(value_name = "SEGMENT")]
    segments: Vec<String>,

    /// Inline JSON request document for a write verb.
    #[arg(long, value_name = "JSON", conflicts_with = "file")]
    data: Option<String>,

    /// Path to a JSON request document for a write verb (`-` reads stdin).
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Page size for a list verb.
    #[arg(long, value_name = "N")]
    limit: Option<u64>,

    /// Starting offset for a list verb.
    #[arg(long, value_name = "N")]
    offset: Option<u64>,

    /// Server-side list filter as `KEY=VALUE` (repeatable).
    #[arg(long = "filter", value_name = "KEY=VALUE")]
    filters: Vec<String>,
}

impl ResourceArgs {
    /// Fold the parsed resource flags into the framework-neutral
    /// [`ResourceInput`] the shared request builders consume.
    fn to_input(&self) -> CliResult<ResourceInput> {
        let mut list = ListParams::new();
        if self.limit.is_some() || self.offset.is_some() {
            list = list.with_page(PageRequest {
                offset: self.offset.unwrap_or(0),
                limit: self.limit,
            });
        }
        for filter in &self.filters {
            let (key, value) = filter.split_once('=').ok_or_else(|| {
                CliError::usage(format!("--filter must be KEY=VALUE, got '{filter}'"))
            })?;
            if key.trim().is_empty() {
                return Err(CliError::usage(format!(
                    "--filter key must not be empty in '{filter}'"
                )));
            }
            list = list.with_filter(key.trim(), value);
        }

        let mut input = ResourceInput::new()
            .with_segments(self.segments.clone())
            .with_list(list);
        if let Some(body) = self.read_body()? {
            input = input.with_body(body);
        }
        Ok(input)
    }

    /// Read and parse the request document from `--data` or `--file`, if either
    /// was given. A malformed document is a usage error before any request is
    /// sent.
    fn read_body(&self) -> CliResult<Option<Value>> {
        let raw = match (&self.data, &self.file) {
            (Some(data), _) => Some(data.clone()),
            (None, Some(path)) => Some(read_file_or_stdin(path)?),
            (None, None) => None,
        };
        match raw {
            Some(text) => {
                let value: Value = serde_json::from_str(&text).map_err(|error| {
                    CliError::usage(format!("request document is not valid JSON: {error}"))
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

fn read_file_or_stdin(path: &Path) -> CliResult<String> {
    if path.as_os_str() == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| {
                CliError::usage(format!(
                    "failed to read request document from stdin: {error}"
                ))
            })?;
        Ok(buffer)
    } else {
        std::fs::read_to_string(path).map_err(|error| {
            CliError::usage(format!(
                "failed to read request document {}: {error}",
                path.display()
            ))
        })
    }
}

/// Build the `ctl` subcommand tree from the registry metadata. One subcommand
/// per registered group, one nested subcommand per verb, each verb carrying the
/// shared global flags plus the resource args. Purely metadata-driven: no
/// resource noun is named here.
pub(crate) fn build_ctl_command(registry: &Registry) -> Command {
    let mut ctl = Command::new(CTL_COMMAND)
        .about(
            "Control Plane API resource commands (issues #361-#365): every registered resource \
             family, dispatched generically through the shared #360 client.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true);

    for group in registry.groups() {
        let mut group_cmd = Command::new(group.name.clone())
            .about(group.about.clone())
            .subcommand_required(true)
            .arg_required_else_help(true);
        for verb in &group.verbs {
            let mut verb_cmd = Command::new(verb.name.clone());
            verb_cmd = ResourceArgs::augment_args(verb_cmd);
            verb_cmd = GlobalArgs::augment_args(verb_cmd);
            // Set the verb's own help LAST: `augment_args` stamps the args
            // struct's doc comment onto the command's `about`, which would
            // otherwise shadow the verb description with "Global flags…".
            verb_cmd = verb_cmd.about(verb.about.clone());
            group_cmd = group_cmd.subcommand(verb_cmd);
        }
        ctl = ctl.subcommand(group_cmd);
    }
    ctl
}

/// Dispatch a matched `ctl <group> <verb>` invocation, translating the outcome
/// into a stable process exit code (mirroring #360's `ops`/`context` entry
/// points).
pub(crate) fn run_resource(registry: &Registry, matches: &ArgMatches) -> i32 {
    match execute(registry, matches) {
        Ok(()) => 0,
        Err(error) => {
            report_error(&error);
            error.exit_class().code()
        }
    }
}

fn execute(registry: &Registry, matches: &ArgMatches) -> CliResult<()> {
    let (group_name, group_matches) = matches
        .subcommand()
        .ok_or_else(|| CliError::usage("specify a resource group; run `ferrogate ctl --help`"))?;
    let (verb_name, verb_matches) = group_matches.subcommand().ok_or_else(|| {
        CliError::usage(format!(
            "specify a verb for '{group_name}'; run `ferrogate ctl {group_name} --help`"
        ))
    })?;
    // Defense in depth: the clap tree only offers registered group/verb pairs,
    // but re-resolve against the registry so any drift is a clean usage error
    // rather than a surprising dispatch.
    registry.resolve(group_name, verb_name)?;

    let global = GlobalArgs::from_arg_matches(verb_matches)
        .map_err(|error| CliError::usage(error.to_string()))?;
    let resource = ResourceArgs::from_arg_matches(verb_matches)
        .map_err(|error| CliError::usage(error.to_string()))?;
    let input = resource.to_input()?;

    // Build the request from the shared metadata-driven router — no hand-rolled
    // path. A clone is kept for the read-only redaction decision because the
    // spec itself is moved into the async send below.
    let spec = build_request(group_name, verb_name, &input)?;
    let redaction_spec = spec.clone();

    let effective = dispatch::resolve_effective(&global)?;
    let credential = resolve_credential(&effective.auth, &ProcessSecretResolver)?;
    let output_format = effective.output;

    let runtime = dispatch::runtime()?;
    let response: ApiResponse = runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport);
        client.send(&spec).await
    })?;

    // Correlation ids are diagnostics → stderr; the payload stays clean on
    // stdout so `--output json` is pipe-safe.
    if let Some(request_id) = &response.request_id {
        eprintln!("request-id: {request_id}");
    }
    if let Some(trace_id) = &response.trace_id {
        eprintln!("trace-id: {trace_id}");
    }

    // Blank one-time secret material on reads before it can reach stdout; a
    // mutation's response is left intact so the operator captures it once.
    let mut body = response.body;
    redact_response(group_name, &redaction_spec, &mut body);

    match output_format {
        OutputFormat::Json => println!("{}", render_json(&body)?),
        OutputFormat::Table => println!("{}", render_table(&body)?),
    }
    Ok(())
}

/// Project an arbitrary Control Plane API response document into a stable
/// human-readable table. Three shapes are handled generically so no per-resource
/// projection is needed: a top-level array (or a common `{items|data|…: [...]}`
/// list envelope) renders as a columnar table keyed by the union of item fields;
/// a single object renders as a `FIELD`/`VALUE` two-column table; a scalar
/// renders directly.
fn render_table(body: &Value) -> CliResult<String> {
    match body {
        Value::Null => Ok("(empty)".to_string()),
        Value::Array(items) => array_table(items),
        Value::Object(map) => {
            for key in ["items", "data", "results", "records"] {
                if let Some(Value::Array(items)) = map.get(key) {
                    return array_table(items);
                }
            }
            object_table(map)
        }
        other => Ok(render_scalar(other)),
    }
}

/// Render an array of items. A homogeneous array of objects becomes a columnar
/// table over the union of keys (in first-seen order); anything else becomes a
/// single `VALUE` column.
fn array_table(items: &[Value]) -> CliResult<String> {
    if items.is_empty() {
        return Ok("(no results)".to_string());
    }
    if items.iter().all(Value::is_object) {
        let mut columns: Vec<String> = Vec::new();
        for item in items {
            if let Value::Object(map) = item {
                for key in map.keys() {
                    if !columns.iter().any(|column| column == key) {
                        columns.push(key.clone());
                    }
                }
            }
        }
        let headers: Vec<String> = columns.iter().map(|column| column.to_uppercase()).collect();
        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|item| {
                columns
                    .iter()
                    .map(|column| {
                        item.get(column)
                            .map(render_scalar)
                            .unwrap_or_else(|| "-".to_string())
                    })
                    .collect()
            })
            .collect();
        return Ok(Table::new(headers, rows)?.render());
    }
    let rows: Vec<Vec<String>> = items.iter().map(|item| vec![render_scalar(item)]).collect();
    Ok(Table::new(vec!["VALUE".to_string()], rows)?.render())
}

/// Render a single object as an aligned `FIELD`/`VALUE` table.
fn object_table(map: &Map<String, Value>) -> CliResult<String> {
    let rows: Vec<Vec<String>> = map
        .iter()
        .map(|(key, value)| vec![key.clone(), render_scalar(value)])
        .collect();
    Ok(Table::new(vec!["FIELD".to_string(), "VALUE".to_string()], rows)?.render())
}

/// Render a JSON scalar without the surrounding quotes a raw `to_string` adds;
/// a nested array/object falls back to compact JSON so a cell stays single-line.
fn render_scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_string(),
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "resource_cmd_test.rs"]
mod resource_cmd_test;
