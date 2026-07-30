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
//! `ferrogate-control-plane-client` and registered onto a
//! [`Registry`](ferrogate_control_plane_client::command::Registry), but nothing exposed them
//! to an operator. This module is that exposure, and it is deliberately
//! **generic**: the whole `ferrogate ctl <group> <verb>` command tree is built
//! from the registry's compile-time metadata
//! ([`GroupDescriptor`](ferrogate_control_plane_client::command::GroupDescriptor) /
//! [`VerbDescriptor`](ferrogate_control_plane_client::command::VerbDescriptor)), and every
//! matched command is routed through the shared
//! [`build_request`](ferrogate_control_plane_client::dispatch::build_request) seam. Adding a
//! resource family in `ferrogate-control-plane-client` therefore requires **no change here**
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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches};
use ferrogate_control_plane_client::action_identity::{ClientActionIdentity, FingerprintEnv};
use ferrogate_control_plane_client::args::GlobalArgs;
use ferrogate_control_plane_client::auth::{resolve_credential, Credential};
use ferrogate_control_plane_client::command::Registry;
use ferrogate_control_plane_client::context::EffectiveContext;
use ferrogate_control_plane_client::dispatch::{build_request, redact_response, secret_fields_for};
use ferrogate_control_plane_client::error::{CliError, CliResult};
use ferrogate_control_plane_client::field_set;
use ferrogate_control_plane_client::output::{render_output, Table};
use ferrogate_control_plane_client::receipt::{
    BareRenderer, MutationPlan, MutationReport, ReceiptRenderer, RenderGate, VerbOutput,
};

use ferrogate_control_plane_client::registry_helpers::ResourceInput;
use ferrogate_control_plane_client::resource::{diverted_secret_document, ListParams};
use ferrogate_control_plane_client::transport::{
    page_cursor_state, page_envelope, ApiResponse, ControlPlaneClient, PageCursorState,
    PageRequest, RawApiResponse, RequestSpec, ReqwestTransport, DEFAULT_PAGE_SIZE, PAGE_ITEM_KEYS,
};
use serde_json::{Map, Value};

use super::dispatch::{self, report_error_for, ProcessSecretResolver};
use super::{confirmation, secret_sink};

/// Top-level namespace command that hosts every registered resource family.
pub(crate) const CTL_COMMAND: &str = "ctl";
const CONFIRM_ARG: &str = "yes";

/// Resource-specific arguments shared by every generic verb: the id path
/// segments, an optional JSON request document (for writes), and list
/// pagination/filters. Reused verbatim across all verbs, so the request shape a
/// verb needs is validated by the shared `ferrogate-control-plane-client` builders (which
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

    /// Set one request-document field as `KEY=VALUE`, repeatable; the value is
    /// always a JSON string.
    ///
    /// `KEY` may be dotted (`quota.max_bytes`) to reach a nested field, with
    /// `\.` for a literal dot in a name. Use `--set-json` for a number,
    /// boolean, null, array, or object. This is the "explicit flags for small
    /// mutations" half of the command contract: a one-field status flip no
    /// longer requires hand-writing the whole document.
    #[arg(
        long = "set",
        value_name = "KEY=VALUE",
        conflicts_with_all = ["data", "file"]
    )]
    set: Vec<String>,

    /// Set one request-document field to a JSON literal as `KEY=JSON`,
    /// repeatable.
    ///
    /// Same dotted-key syntax as `--set`; the value is parsed as JSON, so a
    /// number, boolean, null, array, or object arrives typed.
    #[arg(
        long = "set-json",
        value_name = "KEY=JSON",
        conflicts_with_all = ["data", "file"]
    )]
    set_json: Vec<String>,

    /// Write one-time secret material to PATH with mode 0600 instead of
    /// printing it; the file must not already exist.
    ///
    /// The key a create/rotate returns is replaced on stdout by a marker
    /// naming the file. Only meaningful for a mutating verb in a family that
    /// issues one-time secrets; anywhere else it is refused rather than
    /// silently ignored.
    #[arg(long = "secret-file", value_name = "PATH")]
    secret_file: Option<PathBuf>,

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

    /// Plan a mutating verb without issuing it: print the decision receipt the
    /// call would produce, including the exact request and its action
    /// fingerprint, and send nothing. Accepted by every mutating verb and
    /// echoed as `dry_run` on the receipt; refused on read verbs, which change
    /// nothing to begin with.
    // Deliberately a uniform property of every mutation rather than a
    // per-resource verb: `ops config validate` and `guardrail-policies
    // dry-run` are server-side operations that happen to be named that way,
    // and conflating them with "the client did not send this" is exactly the
    // ambiguity issue #505 closes. The receipt's `dry_run` field reports THIS
    // flag, never the verb's name.
    #[arg(long)]
    dry_run: bool,
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

    /// Read and parse the request document from `--data`, `--file`, or the
    /// per-field `--set`/`--set-json` flags. A malformed document is a usage
    /// error before any request is sent.
    ///
    /// The three sources are mutually exclusive at the clap layer, so there is
    /// no merge order to define here: a document is supplied whole, or it is
    /// assembled from fields.
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
            None => field_set::document_from_flags(&self.set, &self.set_json),
        }
    }

    /// Whether any per-field assignment flag was given.
    fn has_field_flags(&self) -> bool {
        !self.set.is_empty() || !self.set_json.is_empty()
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
            if verb.requires_confirmation() {
                verb_cmd = verb_cmd.arg(
                    Arg::new(CONFIRM_ARG)
                        .long(CONFIRM_ARG)
                        .action(ArgAction::SetTrue)
                        .conflicts_with("dry_run")
                        .help(
                            "Acknowledge this guarded state-changing operation without prompting",
                        ),
                );
            }
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
    // rather than a surprising dispatch. The resolved descriptor is also the
    // input to the #505 render gate below — the binary never decides for itself
    // whether a verb mutates.
    let descriptor = registry.resolve(group_name, verb_name)?;

    let global = GlobalArgs::from_arg_matches(verb_matches)
        .map_err(|error| CliError::usage(error.to_string()))?;
    let resource = ResourceArgs::from_arg_matches(verb_matches)
        .map_err(|error| CliError::usage(error.to_string()))?;
    let effective = dispatch::resolve_effective(&global)?;
    let confirmed = descriptor.requires_confirmation() && verb_matches.get_flag(CONFIRM_ARG);
    confirmation::require(
        descriptor,
        group_name,
        verb_name,
        &resource.segments,
        resource.dry_run,
        confirmed,
        effective.non_interactive,
    )?;

    // Every flag whose applicability depends on the resolved verb is refused
    // here, BEFORE the body is read and before a socket can be opened. The
    // alternative — accepting and ignoring — is the `ca_bundle_path` /
    // pre-#361 `--sort` anti-pattern this family keeps closing: a flag that
    // parses but does nothing reads as a capability the CLI does not have.
    let group_secret_fields = secret_fields_for(group_name);
    if let Some(path) = &resource.secret_file {
        if !descriptor.render_gate().requires_receipt() {
            return Err(CliError::usage(format!(
                "--secret-file applies to mutating verbs that issue one-time key material; \
                 '{group_name} {verb_name}' is a {} verb, and a read's secret fields are \
                 redacted rather than returned",
                descriptor.effect.as_str()
            )));
        }
        if group_secret_fields.is_empty() {
            return Err(CliError::usage(format!(
                "--secret-file applies to families that return one-time key material; \
                 '{group_name}' returns none, so {} would be written empty",
                path.display()
            )));
        }
        if resource.dry_run {
            return Err(CliError::usage(
                "--secret-file has nothing to write under --dry-run: no request is sent, so no \
                 key material is issued"
                    .to_string(),
            ));
        }
    }
    if resource.has_field_flags() && !descriptor.render_gate().requires_receipt() {
        return Err(CliError::usage(format!(
            "--set/--set-json build a request document; '{group_name} {verb_name}' is a {} verb \
             and sends none",
            descriptor.effect.as_str()
        )));
    }

    // Confirmation deliberately precedes this conversion: `--file -` may
    // consume stdin, and a guarded mutation must not lose its prompt merely
    // because its request body also comes from stdin.
    let input = resource.to_input()?;

    // `--data` puts the whole request document in argv, where it survives in
    // shell history and is readable by any local `ps` for the life of the
    // process. `--file`/stdin is the safe alternative, and nothing said so.
    // Keyed on the document actually passed, so the note fires on the creates
    // that really do carry a credential and stays quiet otherwise.
    if resource.data.is_some() {
        if let Some(body) = &input.body {
            if let Some(warning) = field_set::argv_credential_warning(body, group_secret_fields) {
                eprintln!("{warning}");
            }
        }
    }

    // `--sort` is honest about being unhonored. A structural parse of
    // `docs/openapi/admin-api.openapi.json` finds **zero** operations declaring
    // a `sort` query parameter (pinned by `sort_is_not_yet_an_openapi_query_
    // parameter` in `ferrogate-control-plane-client`), so the key reaches the server and is
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

    let raw_media_type = descriptor.raw_response_media_type();
    if let Some(media_type) = raw_media_type {
        if global.output.is_some() {
            return Err(CliError::usage(format!(
                "--output does not apply to '{group_name} {verb_name}'; the command writes its \
                 {media_type} export bytes to stdout unchanged"
            )));
        }
        if resource.all_pages {
            return Err(CliError::usage(format!(
                "--all-pages does not apply to the raw '{group_name} {verb_name}' export"
            )));
        }
    }

    let credential = resolve_credential(&effective.auth, &ProcessSecretResolver)?;
    let output_format = effective.output;
    // One identity per operator action (issue #548), minted before the verb is
    // routed so a read and a mutation are attributed the same way, and so every
    // page of an `--all-pages` walk shares one `action_id`. It is handed to the
    // transport AND to the mutation plan; both hold clones sharing one
    // server-time slot, so the receipt reports the action the server saw.
    let identity = ClientActionIdentity::mint(&effective, &FingerprintEnv::from_process())?;

    if let Some(media_type) = raw_media_type {
        write_raw_output(spec, effective, credential, identity, media_type)?;
        return Ok(());
    }

    // Reserved before the request leaves the process, so an unusable sink is a
    // refusal with nothing sent rather than a key issued into the void.
    let secret_file = match &resource.secret_file {
        Some(path) => Some(secret_sink::SecretFile::reserve(path)?),
        None => None,
    };

    // The #505 render gate. This `match` is the whole enforcement: the
    // `Receipt` arm holds a `ReceiptRenderer`, which has no `render(Value)`
    // method, and `VerbOutput` wraps a private payload, so there is no
    // expression in this function — or any other — that turns a mutating verb
    // plus a raw body into printable output. Adding a resource family cannot
    // reintroduce a bare mutation response, because the family never touches
    // this code at all.
    // A mutating verb yields a receipt on EVERY terminal path, so the failure
    // travels alongside the output instead of short-circuiting the render. It
    // is propagated below, after the receipt has reached stdout.
    // Wrapped in a closure so an early exit cannot strand the reserved secret
    // file on disk: a zero-byte reservation left behind would make the next
    // run's `create_new` refusal fire on a file holding nothing.
    let rendered = (|| -> CliResult<(VerbOutput, Option<CliError>)> {
        match descriptor.render_gate() {
            RenderGate::Bare(renderer) => {
                if resource.dry_run {
                    return Err(CliError::usage(format!(
                        "--dry-run applies to mutating verbs; '{group_name} {verb_name}' is a \
                         {} verb and changes nothing",
                        descriptor.effect.as_str()
                    )));
                }
                Ok((
                    read_output(
                        renderer,
                        group_name,
                        &resource,
                        spec,
                        &redaction_spec,
                        effective,
                        credential,
                        identity,
                    )?,
                    None,
                ))
            }
            RenderGate::Receipt(renderer) => {
                if resource.all_pages {
                    return Err(CliError::usage(format!(
                        "--all-pages is a list-walking flag; '{group_name} {verb_name}' is a \
                         mutating verb and returns one document"
                    )));
                }
                Ok(mutation_output(
                    renderer,
                    group_name,
                    &input.segments,
                    spec,
                    effective,
                    credential,
                    identity,
                    resource.dry_run,
                )?
                .into_parts())
            }
        }
    })();
    let (mut output, failure) = match rendered {
        Ok(pair) => pair,
        Err(error) => {
            if let Some(file) = secret_file {
                if let Some(note) = file.discard() {
                    eprintln!("{note}");
                }
            }
            return Err(error);
        }
    };

    // Route one-time key material off stdout when a sink was named, and say so
    // when one was not. `divert_response_secrets` is the only mutable access
    // the render gate grants and it hands back just the secrets, so this cannot
    // become a way to recover a bare mutation body.
    let diverted = match &secret_file {
        Some(_) => output.divert_response_secrets(group_secret_fields),
        None => Vec::new(),
    };
    if secret_file.is_none() {
        let exposed = output.response_secret_names(group_secret_fields);
        if !exposed.is_empty() {
            eprintln!("{}", secret_sink::stdout_exposure_warning(&exposed));
        }
    }

    // Correlation ids are diagnostics → stderr; the payload stays clean on
    // stdout so `--output json` is pipe-safe. A receipt carries them as
    // attested fields too, so a piped receipt is self-contained.
    if let Some(receipt) = output.receipt() {
        if let Some(request_id) = &receipt.correlation.request_id.value {
            eprintln!("request-id: {request_id}");
        }
        if let Some(trace_id) = &receipt.correlation.trace_id.value {
            eprintln!("trace-id: {trace_id}");
        }
    }

    println!("{}", render_output(output_format, &output, render_table)?);

    // The sink is committed AFTER the receipt reaches stdout: the receipt is
    // the audit record of a mutation that already happened, so it must not be
    // withheld because writing the key file failed.
    if let Some(file) = secret_file {
        if diverted.is_empty() {
            if let Some(note) = file.discard() {
                eprintln!("{note}");
            }
        } else {
            let notice = secret_sink::wrote_notice(file.path(), &diverted);
            file.commit(&diverted_secret_document(&diverted))?;
            eprintln!("{notice}");
        }
    }

    // A single-page list must never look complete when it is not. The notice
    // is a diagnostic → stderr, so it cannot corrupt a piped JSON payload.
    // Only a read produces pages at all.
    if let Some(body) = output.body() {
        if !resource.all_pages {
            if let Some(notice) =
                truncation_notice(body, resource.offset.unwrap_or(0), resource.limit)
            {
                eprintln!("{notice}");
            }
        }
    }

    // A failed mutation still exits on the error's own class — the receipt on
    // stdout is the audit record, not an absolution. Returning here (rather
    // than before the render) is what makes the receipt the output contract of
    // a mutating verb on the failing paths too: the operator's pipeline records
    // `outcome: rejected` or `outcome: unknown` with the target fingerprint,
    // and the prose goes to stderr as it always did.
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Write an export response to stdout byte-for-byte. No renderer or implicit
/// newline is allowed on this path because stdout is the durable artifact.
fn write_raw_output(
    spec: RequestSpec,
    effective: EffectiveContext,
    credential: Option<Credential>,
    identity: ClientActionIdentity,
    media_type: &str,
) -> CliResult<()> {
    let runtime = dispatch::runtime()?;
    let response: RawApiResponse = runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport, identity);
        client.send_raw(&spec, media_type).await
    })?;

    if let Some(request_id) = &response.request_id {
        eprintln!("request-id: {request_id}");
    }
    if let Some(trace_id) = &response.trace_id {
        eprintln!("trace-id: {trace_id}");
    }

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&response.body)
        .and_then(|()| stdout.flush())
        .map_err(|error| CliError::transport(format!("failed to write export to stdout: {error}")))
}

/// Execute a non-mutating verb and gate its body into a [`VerbOutput`].
///
/// Unchanged behaviour from before #505 — pagination, one-time-secret
/// redaction, and the cursor-offset refusal all still happen here — except
/// that the body now leaves through the render gate's `BareRenderer` instead
/// of being printed directly.
#[allow(clippy::too_many_arguments)]
fn read_output(
    renderer: BareRenderer<'_>,
    group_name: &str,
    resource: &ResourceArgs,
    spec: RequestSpec,
    redaction_spec: &RequestSpec,
    effective: EffectiveContext,
    credential: Option<Credential>,
    identity: ClientActionIdentity,
) -> CliResult<VerbOutput> {
    let all_pages = resource.all_pages;
    let page_size = resource.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    let runtime = dispatch::runtime()?;
    let response: ApiResponse = runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport, identity);
        if all_pages {
            client.send_all_pages(&spec, page_size).await
        } else {
            client.send(&spec).await
        }
    })?;

    if let Some(request_id) = &response.request_id {
        eprintln!("request-id: {request_id}");
    }
    if let Some(trace_id) = &response.trace_id {
        eprintln!("trace-id: {trace_id}");
    }

    // Blank one-time secret material on reads before it can reach stdout.
    let mut body = response.body;
    redact_response(group_name, redaction_spec, &mut body);

    // A cursor endpoint ignores `--offset`, so page N is page ONE with exit 0 —
    // checked BEFORE anything is printed, so the wrong page never reaches stdout
    // to be piped somewhere.
    if let Some(refusal) = cursor_offset_refusal(&body, resource.offset, &redaction_spec.path) {
        return Err(CliError::usage(refusal));
    }

    Ok(renderer.render(body))
}

/// Plan and (unless it is a dry run) execute a mutating verb, returning its
/// decision receipt.
///
/// The dry-run branch is deliberately taken **before** the async runtime is
/// started and before any transport is constructed: `MutationPlan::dry_run`
/// takes no client, so on this path no `ReqwestTransport` is ever built and no
/// socket is ever opened. That is the structural half of "a dry run issues no
/// state-changing request"; the transport-level assertion lives in
/// `ferrogate-control-plane-client`'s `receipt_test.rs`.
#[allow(clippy::too_many_arguments)]
fn mutation_output(
    renderer: ReceiptRenderer<'_>,
    group_name: &str,
    segments: &[String],
    spec: RequestSpec,
    effective: EffectiveContext,
    credential: Option<Credential>,
    identity: ClientActionIdentity,
    dry_run: bool,
) -> CliResult<MutationReport> {
    let plan = MutationPlan::new(
        renderer, group_name, spec, segments, &effective, &identity, dry_run,
    )?;
    if plan.is_dry_run() {
        return Ok(MutationReport::from(plan.dry_run()));
    }
    let runtime = dispatch::runtime()?;
    // Building the transport is the last thing that can fail without a
    // receipt: it is a local TLS/timeout configuration error, so nothing was
    // sent and there is no mutation to attest. Everything from `plan.send`
    // onwards produces a receipt whatever happens — 2xx, error envelope, or a
    // connection that died without an answer.
    runtime.block_on(async move {
        let transport = ReqwestTransport::new(&effective)?;
        let client = ControlPlaneClient::new(effective, credential, transport, identity);
        Ok(plan.send(&client).await)
    })
}

/// Refuse a `--offset` the endpoint provably did not honor.
///
/// A cursor-paginated endpoint parses `cursor`, not `offset`: `--offset 50`
/// against one returns page **one** and exits 0. That is the quiet half of the
/// same defect as the `--all-pages` storm (#352 review) and the worse half —
/// the storm at least errors eventually, while this hands an operator page one
/// labelled as page N on a money-audit surface. `--all-pages` is refused inside
/// the walk itself; this is the single-page path, which never reaches it.
///
/// `None` when no offset was asked for, or when the response is not a cursor
/// page — an offset-paginated endpoint honors offsets, and a non-list document
/// has no pages at all. Pure.
fn cursor_offset_refusal(body: &Value, offset: Option<u64>, path: &str) -> Option<String> {
    let offset = offset.filter(|offset| *offset > 0)?;
    let state = page_cursor_state(body)?;
    let resume = match &state {
        PageCursorState::Resume { key, value } => format!(
            "This page's continuation is {key}={value}; pass it back with --filter using the \
             cursor parameter {path} documents"
        ),
        _ => format!(
            "Page it with --filter and the cursor parameter {path} documents, or re-run without \
             --offset for the first page"
        ),
    };
    Some(format!(
        "--offset {offset} was ignored by {path}: it is cursor-paginated, so the rows above are \
         page ONE, not the page you asked for. Refusing rather than returning the wrong page with \
         exit 0. {resume}"
    ))
}

/// Build the operator-facing notice that a single-page list is — or may be —
/// incomplete, or `None` when the page is provably the whole collection.
///
/// This is what keeps the default one-page list from being the silent
/// truncation the issue forbids: whenever rows were left behind, or whenever
/// the server gave us no way to know, the operator is told so and pointed at
/// `--all-pages` — or, on a cursor endpoint, at the cursor, since `--all-pages`
/// cannot walk one.
///
/// `requested_limit` is the operator's `--limit`, which is frequently absent.
/// The page size that actually applied then comes from the envelope's own
/// `limit` field — carried by every paginated list schema in the contract.
/// Consulting only the flag (as the first cut did) meant a bare `ferrogate ctl
/// <group> list` against an endpoint with a server-side default page size and
/// no `total` produced no notice at all: the exact default invocation an
/// operator is most likely to run, and the one where a truncated page is least
/// likely to be suspected. Pure, so every branch is unit-testable.
fn truncation_notice(body: &Value, offset: u64, requested_limit: Option<u64>) -> Option<String> {
    let envelope = page_envelope(body)?;
    let returned = envelope.items.len() as u64;
    // A cursor page's completeness is decided by its own cursor, not by
    // arithmetic on a window it never used: a full page with a null
    // `next_cursor` IS the whole remainder, and a page whose cursor is set has
    // more rows even when it came back short. Pointing such an operator at
    // `--all-pages` — which now refuses cursor endpoints, correctly — would be
    // advice that cannot work.
    if envelope.cursor {
        return match page_cursor_state(body)? {
            PageCursorState::Resume { key, value } => Some(format!(
                "note: showing {returned} rows; this endpoint pages by cursor and reported \
                 {key}={value}, so more rows exist — re-run with --filter and the cursor \
                 parameter this endpoint documents (--all-pages cannot walk a cursor endpoint)"
            )),
            PageCursorState::Exhausted => None,
            PageCursorState::Unknown => Some(format!(
                "note: showing {returned} rows from a cursor-paginated endpoint that reported no \
                 continuation either way; more rows may exist"
            )),
        };
    }
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
