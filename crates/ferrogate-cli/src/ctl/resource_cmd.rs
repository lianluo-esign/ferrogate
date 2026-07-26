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
use ferrogate_cli_core::dispatch::{build_request, redact_response, secret_fields_for};
use ferrogate_cli_core::error::{CliError, CliResult};
use ferrogate_cli_core::output::{render_json, OutputFormat, Table};
use ferrogate_cli_core::registry_helpers::ResourceInput;
use ferrogate_cli_core::resource::ListParams;
use ferrogate_cli_core::transport::{
    page_envelope, ApiResponse, ControlPlaneClient, PageRequest, ReqwestTransport,
    DEFAULT_PAGE_SIZE, PAGE_ITEM_KEYS,
};
use serde_json::{Map, Value};

use super::dispatch::{self, report_error_for, ProcessSecretResolver};

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

    /// Server-side sort key for a list verb; prefix with `-` for descending.
    /// Repeatable and order-preserving, so the first key is the primary sort.
    /// NOT HONORED BY THE SERVER TODAY: no Control Plane API operation declares
    /// a `sort` query parameter, so the key is forwarded verbatim and currently
    /// ignored; a note is printed to stderr on every use.
    // `allow_hyphen_values` is required, not cosmetic: without it clap reads
    // the documented descending form `--sort -created_at` as an unknown `-c`
    // flag, making descending sort unreachable from the command line.
    #[arg(long = "sort", value_name = "FIELD", allow_hyphen_values = true)]
    sorts: Vec<String>,

    /// Fetch every page of a list verb instead of a single server page, using
    /// `--limit` as the page size. Mutually exclusive with `--offset`, which
    /// selects one page.
    #[arg(long, conflicts_with = "offset")]
    all_pages: bool,
}

impl ResourceArgs {
    /// Fold the parsed resource flags into the framework-neutral
    /// [`ResourceInput`] the shared request builders consume.
    fn to_input(&self) -> CliResult<ResourceInput> {
        let mut list = ListParams::new();
        // Under --all-pages the walker owns the cursor, so no offset/limit is
        // baked into the spec here; `--limit` becomes the walk's page size.
        if !self.all_pages && (self.limit.is_some() || self.offset.is_some()) {
            list = list.with_page(PageRequest {
                offset: self.offset.unwrap_or(0),
                limit: self.limit,
            });
        }
        for sort in &self.sorts {
            let key = sort.trim();
            if key.is_empty() {
                return Err(CliError::usage("--sort key must not be empty".to_string()));
            }
            // `allow_hyphen_values` (needed for the descending `-created_at`
            // form) also makes clap hand a following *flag* to `--sort`:
            // `--sort --output json` parses `--output` as the sort key and
            // `json` as a stray positional segment. A field name never begins
            // with `--`, so this is a forgotten value, not a sort key.
            if key.starts_with("--") {
                return Err(CliError::usage(format!(
                    "--sort expected a field name but got the flag '{key}'; \
                     a sort key never begins with '--' (did you mean `--sort <FIELD> {key}`?)"
                )));
            }
            list = list.with_sort(key);
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
            // The invoked group's one-time secret fields are redacted from the
            // error's `details` payload exactly as they are from a success
            // body: a server error that echoes the rejected request must not be
            // the one path that leaks key material to stderr.
            report_error_for(&error, invoked_secret_fields(matches));
            error.exit_class().code()
        }
    }
}

/// The one-time secret fields of the group named on the command line, or an
/// empty slice when no group was matched (a bare `ferrogate ctl` usage error).
/// Read straight off the parsed matches so it is available on the error path,
/// where `execute`'s locals are gone.
fn invoked_secret_fields(matches: &ArgMatches) -> &'static [&'static str] {
    match matches.subcommand() {
        Some((group, _)) => secret_fields_for(group),
        None => &[],
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

    // `--sort` is honest about being unhonored. A structural parse of
    // `docs/openapi/admin-api.openapi.json` finds **zero** operations declaring
    // a `sort` query parameter (pinned by `sort_is_not_yet_an_openapi_query_
    // parameter` in `ferrogate-cli-core`), so the key reaches the server and is
    // ignored. Forwarding it verbatim is the right client design — sort order is
    // only meaningful over the whole collection, so re-sorting a page locally
    // would be a lie — but a flag documented as working that provably does
    // nothing is the same ignored-field anti-pattern as a silently dropped
    // `ca_bundle_path`, just wearing the server's clothes. Saying so on stderr
    // costs one line and keeps the operator from trusting an order they did not
    // get.
    if !resource.sorts.is_empty() {
        eprintln!(
            "note: --sort is forwarded to the server verbatim, but no Control Plane API \
             operation declares a 'sort' query parameter yet — the returned order is the \
             server's default, not the one you asked for"
        );
    }

    // Build the request from the shared metadata-driven router — no hand-rolled
    // path. A clone is kept for the read-only redaction decision because the
    // spec itself is moved into the async send below.
    let spec = build_request(group_name, verb_name, &input)?;
    let redaction_spec = spec.clone();

    let effective = dispatch::resolve_effective(&global)?;
    let credential = resolve_credential(&effective.auth, &ProcessSecretResolver)?;
    let output_format = effective.output;

    let all_pages = resource.all_pages;
    let page_size = resource.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    let runtime = dispatch::runtime()?;
    let response: ApiResponse = runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport);
        if all_pages {
            client.send_all_pages(&spec, page_size).await
        } else {
            client.send(&spec).await
        }
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

    // A single-page list must never look complete when it is not. The notice
    // is a diagnostic → stderr, so it cannot corrupt a piped JSON payload.
    if !all_pages {
        if let Some(notice) = truncation_notice(&body, resource.offset.unwrap_or(0), resource.limit)
        {
            eprintln!("{notice}");
        }
    }
    Ok(())
}

/// Build the operator-facing notice that a single-page list is — or may be —
/// incomplete, or `None` when the page is provably the whole collection.
///
/// This is what keeps the default one-page list from being the silent
/// truncation the issue forbids: whenever rows were left behind, or whenever
/// the server gave us no way to know, the operator is told so and pointed at
/// `--all-pages`. Pure, so every branch is unit-testable.
///
/// `requested_limit` is the operator's `--limit`, which is frequently absent.
/// The page size that actually applied then comes from the envelope's own
/// `limit` field — carried by every paginated list schema in the contract.
/// Consulting only the flag (as the first cut did) meant a bare `ferrogate ctl
/// <group> list` against an endpoint with a server-side default page size and
/// no `total` produced no notice at all: the exact default invocation an
/// operator is most likely to run, and the one where a truncated page is least
/// likely to be suspected.
fn truncation_notice(body: &Value, offset: u64, requested_limit: Option<u64>) -> Option<String> {
    let envelope = page_envelope(body)?;
    let returned = envelope.items.len() as u64;
    match envelope.total {
        Some(total) if offset.saturating_add(returned) < total => Some(format!(
            "note: showing {returned} of {total} rows (offset {offset}); \
             re-run with --all-pages to fetch every row"
        )),
        Some(_) => None,
        // With no server-reported total, a page that came back exactly full is
        // indistinguishable from a truncated one. Say that plainly instead of
        // implying completeness.
        None => match requested_limit.or(envelope.limit) {
            Some(limit) if returned > 0 && returned >= limit => Some(format!(
                "note: returned a full page of {returned} rows and the server reported no total; \
                 more rows may exist — re-run with --all-pages to be sure"
            )),
            _ => None,
        },
    }
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
            for key in PAGE_ITEM_KEYS {
                if let Some(Value::Array(items)) = map.get(key) {
                    return list_envelope_table(map, key, items);
                }
            }
            object_table(map)
        }
        other => Ok(render_scalar(other)),
    }
}

/// Render a list envelope as the item table followed by the envelope's own
/// metadata (`total`, `next_offset`, …).
///
/// Rendering only the item array — as the first cut did — made a truncated
/// page visually identical to a complete one in the default output format,
/// because `total` was silently discarded along with every other sibling key.
fn list_envelope_table(
    map: &Map<String, Value>,
    items_key: &str,
    items: &[Value],
) -> CliResult<String> {
    let table = array_table(items)?;
    let metadata: Map<String, Value> = map
        .iter()
        .filter(|(key, _)| key.as_str() != items_key)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if metadata.is_empty() {
        return Ok(table);
    }
    Ok(format!("{table}\n\n{}", object_table(&metadata)?))
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
