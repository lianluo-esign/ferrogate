// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Extensible command dispatch skeleton (issue #360).
//!
//! The problem this solves: the client will grow to cover 200+ Control Plane
//! API operations across many resource families (#361–#365). If each family
//! were hand-wired into one giant match, adding a resource would touch
//! unrelated code and drift from the OpenAPI contract. Instead each resource
//! family is a [`CommandGroup`] that declares its verbs — and the OpenAPI
//! `operationId` each verb implements — as **compile-time metadata**. A
//! [`Registry`] collects those declarations and derives:
//!
//! * help/discovery output for `--help`, and
//! * a coverage manifest (`operationId` set) that the #365 OpenAPI parity gate
//!   compares against the contract to fail when the API adds an uncovered
//!   operation.
//!
//! Adding a resource family means adding a module that implements
//! [`CommandGroup`] and registering it. No transport, renderer, context, or
//! other family changes. This is the "extensible without runtime plugins"
//! contract from the epic: extension is compile-time registration, not an
//! opaque dynamic command loader.

use std::collections::BTreeSet;

use crate::error::{CliError, CliResult};

/// Whether a verb changes Control-Plane state, and therefore whether it owes
/// the operator a [`MutationReceipt`](crate::receipt::MutationReceipt)
/// (issue #505).
///
/// This is *registry* metadata, not a rendering hint: it is the field the
/// render gate ([`VerbDescriptor::render_gate`]) consumes to decide which
/// output shape is even constructible for a verb. Because every API verb must
/// choose [`VerbDescriptor::read`] or [`VerbDescriptor::mutating`] at
/// construction (there is no effect-less API constructor), a newly added verb
/// that nobody classified does not compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbEffect {
    /// A safe read of Control-Plane state (`GET`/`HEAD`). Renders the server's
    /// body verbatim; there is nothing to attest.
    Read,
    /// A state-changing call (`POST`/`PUT`/`PATCH`/`DELETE`). The only
    /// sanctioned output is a `MutationReceipt`.
    Mutating,
    /// Handled entirely client-side (`context use`, `context list`): no request
    /// leaves the process and no Control-Plane object changes, so there is no
    /// governance decision, audit row, or rollback pointer to report. Local
    /// state (the context store) is the operator's own file, not a governed
    /// object.
    Local,
}

impl VerbEffect {
    /// Stable spelling for help text, JSON receipts, and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            VerbEffect::Read => "read",
            VerbEffect::Mutating => "mutating",
            VerbEffect::Local => "local",
        }
    }

    /// Whether this effect changes Control-Plane state.
    pub fn is_mutating(self) -> bool {
        matches!(self, VerbEffect::Mutating)
    }
}

/// What a verb does with the request document the operator supplies.
///
/// [`VerbEffect`] answers *does this change state*; this answers *does the
/// operator's document reach the server, and does it overwrite what is already
/// there*. The two questions are independent, and conflating them is how
/// `ferrogate ctl virtual-keys revoke <id> --set reason=compromised` came to
/// parse, assemble a body, and have that body dropped by the builder while the
/// command exited 0 — the `delete` verb is mutating and sends no document at
/// all. `replace` is the mirror case: mutating, sends a document, and clears
/// every field the document omits.
///
/// It is registry metadata rather than a check against a verb name so a family
/// that adds a body-less lifecycle action states the fact once, at the
/// declaration, instead of every flag learning a list of verb names.
/// `declared_request_document_matches_the_builder` (in `receipt_test.rs`,
/// beside the equivalent guard on [`VerbEffect`]) rebuilds every registered
/// verb's request and fails when a declaration and its builder disagree, so
/// the declaration cannot drift away from what really goes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDocument {
    /// The builder sends no request body (`GET`, `DELETE`, a body-less
    /// lifecycle action). A document supplied on the command line would be
    /// assembled and then discarded, so it is refused instead.
    None,
    /// The body is a partial document: a field it omits keeps whatever the
    /// server already holds (`POST` create, `PATCH` update). Assembling it one
    /// field at a time is safe.
    Partial,
    /// The body replaces the stored document wholesale (`PUT`): a field the
    /// document omits is cleared. Assembling it one field at a time turns
    /// "change this field" into "delete the others", so per-field flags are
    /// refused here even though the verb does carry a body.
    Full,
}

impl RequestDocument {
    /// Stable spelling for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestDocument::None => "none",
            RequestDocument::Partial => "partial",
            RequestDocument::Full => "full",
        }
    }

    /// Whether the builder forwards an operator-supplied document at all.
    pub fn is_sent(self) -> bool {
        !matches!(self, RequestDocument::None)
    }
}

/// Whether a mutating verb requires the operator to confirm intent before the
/// client sends its request.
///
/// This is explicit registry metadata rather than a check against a resource
/// or verb name. The generic CLI dispatcher can therefore enforce the same
/// policy for every current and future command family without learning any
/// provider or product-specific routing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationPolicy {
    /// The operation does not require an additional client-side confirmation.
    None,
    /// The operation requires an interactive confirmation or an explicit
    /// `--yes` before the request may leave the process.
    Required,
}

/// How a successful response body must leave the CLI process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseMode {
    /// Decode the body as JSON and pass it through the normal table/JSON
    /// renderer.
    Structured,
    /// Preserve the response bytes exactly and write them directly to stdout.
    /// The media type is also sent in the request's `Accept` header.
    Raw { media_type: String },
}

/// Metadata for one verb (operation) within a resource family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbDescriptor {
    /// Verb name as typed on the command line (e.g. `list`, `get`, `create`).
    pub name: String,
    /// One-line help.
    pub about: String,
    /// The OpenAPI `operationId` this verb invokes, when it maps to exactly
    /// one operation. `None` marks a purely local verb (e.g. `context use`)
    /// that the coverage gate must not expect in the contract.
    pub operation_id: Option<String>,
    /// Whether the verb changes state — the render gate's input (issue #505).
    pub effect: VerbEffect,
    /// Whether the CLI must confirm operator intent before sending the request.
    pub confirmation: ConfirmationPolicy,
    /// What the verb's builder does with an operator-supplied request document.
    request_document: RequestDocument,
    /// Whether the response is structured CLI data or a byte-faithful export.
    pub response_mode: ResponseMode,
    /// Required query values supplied as positional CLI segments after the
    /// operation's OpenAPI path parameters.
    ///
    /// Most required query parameters use [`crate::resource::ListParams`]. A
    /// small number are intentionally positional because they identify the
    /// target of a mutation (currently `asset-channels set <...> <version>`).
    /// Keeping that exception in verb metadata lets registry-wide tooling
    /// derive the complete positional arity from the OpenAPI path plus this
    /// explicit delta, instead of guessing what a permissive builder accepts.
    positional_query_segments: usize,
}

impl VerbDescriptor {
    /// A **read-only** verb bound to a single Control Plane API operation.
    ///
    /// There is deliberately no effect-agnostic `api()` constructor: an author
    /// adding a verb must state whether it mutates, and a misclassification is
    /// caught by `receipt_test.rs`, which rebuilds every registered verb's
    /// [`RequestSpec`](crate::transport::RequestSpec) and compares the declared
    /// effect against the HTTP method the family builder actually emits.
    pub fn read(
        name: impl Into<String>,
        about: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> VerbDescriptor {
        VerbDescriptor {
            name: name.into(),
            about: about.into(),
            operation_id: Some(operation_id.into()),
            effect: VerbEffect::Read,
            confirmation: ConfirmationPolicy::None,
            request_document: RequestDocument::None,
            response_mode: ResponseMode::Structured,
            positional_query_segments: 0,
        }
    }

    /// A read whose successful response is an export artifact, not a document
    /// for the table/JSON renderer.
    pub fn raw_read(
        name: impl Into<String>,
        about: impl Into<String>,
        operation_id: impl Into<String>,
        media_type: impl Into<String>,
    ) -> VerbDescriptor {
        VerbDescriptor {
            name: name.into(),
            about: about.into(),
            operation_id: Some(operation_id.into()),
            effect: VerbEffect::Read,
            confirmation: ConfirmationPolicy::None,
            request_document: RequestDocument::None,
            response_mode: ResponseMode::Raw {
                media_type: media_type.into(),
            },
            positional_query_segments: 0,
        }
    }

    /// A **state-changing** verb bound to a single Control Plane API operation.
    /// Its only renderable output is a
    /// [`MutationReceipt`](crate::receipt::MutationReceipt).
    pub fn mutating(
        name: impl Into<String>,
        about: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> VerbDescriptor {
        VerbDescriptor {
            name: name.into(),
            about: about.into(),
            operation_id: Some(operation_id.into()),
            effect: VerbEffect::Mutating,
            confirmation: ConfirmationPolicy::None,
            request_document: RequestDocument::Partial,
            response_mode: ResponseMode::Structured,
            positional_query_segments: 0,
        }
    }

    /// A state-changing verb that must not be sent until the operator confirms
    /// it interactively or passes the explicit `--yes` acknowledgement.
    pub fn mutating_with_confirmation(
        name: impl Into<String>,
        about: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> VerbDescriptor {
        VerbDescriptor {
            name: name.into(),
            about: about.into(),
            operation_id: Some(operation_id.into()),
            effect: VerbEffect::Mutating,
            confirmation: ConfirmationPolicy::Required,
            request_document: RequestDocument::Partial,
            response_mode: ResponseMode::Structured,
            positional_query_segments: 0,
        }
    }

    /// A verb handled entirely client-side (no API operation).
    pub fn local(name: impl Into<String>, about: impl Into<String>) -> VerbDescriptor {
        VerbDescriptor {
            name: name.into(),
            about: about.into(),
            operation_id: None,
            effect: VerbEffect::Local,
            confirmation: ConfirmationPolicy::None,
            request_document: RequestDocument::None,
            response_mode: ResponseMode::Structured,
            positional_query_segments: 0,
        }
    }

    /// Declare that this verb's builder sends no request body, so an
    /// operator-supplied document would be discarded rather than delivered.
    ///
    /// `delete` and the DELETE-shaped lifecycle verbs (`virtual-keys revoke`)
    /// are the current members: they are mutating, so effect alone put them on
    /// the same side of every body-related check as `update`.
    pub fn without_request_body(mut self) -> VerbDescriptor {
        self.request_document = RequestDocument::None;
        self
    }

    /// Declare that this verb sends an operator-supplied **partial** document
    /// even though it does not change Control-Plane state.
    ///
    /// [`VerbDescriptor::read`] defaults to [`RequestDocument::None`] because
    /// nearly every read is a `GET`. The exception is a `POST`ed dry-run
    /// evaluator (`x402-spend-policies evaluate`): the operator's document is
    /// the *subject* being evaluated, it reaches the server verbatim, and
    /// nothing is stored — so refusing `--data`/`--set` on it would reject the
    /// only input the verb has.
    pub fn with_request_body(mut self) -> VerbDescriptor {
        self.request_document = RequestDocument::Partial;
        self
    }

    /// Declare that this verb's body **replaces** the stored document, so a
    /// field the document omits is cleared rather than preserved (`PUT`).
    pub fn replacing_whole_document(mut self) -> VerbDescriptor {
        self.request_document = RequestDocument::Full;
        self
    }

    /// What this verb's builder does with an operator-supplied document.
    pub fn request_document(&self) -> RequestDocument {
        self.request_document
    }

    /// Declare required query values that the CLI accepts as positional
    /// segments after the operation's path parameters.
    pub fn with_positional_query_segments(mut self, count: usize) -> VerbDescriptor {
        self.positional_query_segments = count;
        self
    }

    /// Number of required query values supplied positionally by this verb.
    pub fn positional_query_segments(&self) -> usize {
        self.positional_query_segments
    }

    /// Whether this verb changes Control-Plane state.
    pub fn is_mutating(&self) -> bool {
        self.effect.is_mutating()
    }

    /// Whether the generic CLI dispatcher must confirm intent before sending
    /// this verb's request.
    pub fn requires_confirmation(&self) -> bool {
        self.confirmation == ConfirmationPolicy::Required
    }

    /// The media type of a response that must bypass structured rendering.
    pub fn raw_response_media_type(&self) -> Option<&str> {
        match &self.response_mode {
            ResponseMode::Structured => None,
            ResponseMode::Raw { media_type } => Some(media_type),
        }
    }
}

/// Metadata for one resource family (a noun with its verbs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDescriptor {
    /// Group name as typed on the command line (e.g. `tenants`, `context`).
    pub name: String,
    /// One-line help.
    pub about: String,
    /// Verbs offered by this group.
    pub verbs: Vec<VerbDescriptor>,
}

impl GroupDescriptor {
    /// Construct a group descriptor.
    pub fn new(
        name: impl Into<String>,
        about: impl Into<String>,
        verbs: Vec<VerbDescriptor>,
    ) -> GroupDescriptor {
        GroupDescriptor {
            name: name.into(),
            about: about.into(),
            verbs,
        }
    }

    /// Find a verb by name.
    pub fn verb(&self, name: &str) -> Option<&VerbDescriptor> {
        self.verbs.iter().find(|verb| verb.name == name)
    }
}

/// A resource family. Implementors are typically zero-sized types that only
/// return their static [`GroupDescriptor`]; execution wiring (Clap subcommand
/// parsing and request building) is layered on top by later issues without
/// changing this trait.
pub trait CommandGroup {
    /// The family's compile-time metadata.
    fn descriptor(&self) -> GroupDescriptor;
}

/// The set of registered command groups.
#[derive(Debug, Default)]
pub struct Registry {
    groups: Vec<GroupDescriptor>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry { groups: Vec::new() }
    }

    /// Register a command group. Rejects a duplicate group name or a duplicate
    /// verb name within the group — both are programming errors that would
    /// otherwise produce an ambiguous command surface, so they fail loudly at
    /// startup (and in tests) instead of silently shadowing.
    pub fn register(&mut self, group: &dyn CommandGroup) -> CliResult<()> {
        let descriptor = group.descriptor();
        if self
            .groups
            .iter()
            .any(|existing| existing.name == descriptor.name)
        {
            return Err(CliError::usage(format!(
                "duplicate command group '{}' registered",
                descriptor.name
            )));
        }
        let mut seen = BTreeSet::new();
        for verb in &descriptor.verbs {
            if !seen.insert(verb.name.clone()) {
                return Err(CliError::usage(format!(
                    "command group '{}' declares duplicate verb '{}'",
                    descriptor.name, verb.name
                )));
            }
        }
        self.groups.push(descriptor);
        Ok(())
    }

    /// All registered groups, in registration order.
    pub fn groups(&self) -> &[GroupDescriptor] {
        &self.groups
    }

    /// Find a group by name.
    pub fn group(&self, name: &str) -> Option<&GroupDescriptor> {
        self.groups.iter().find(|group| group.name == name)
    }

    /// Resolve a `<group> <verb>` invocation to its verb descriptor, or a
    /// usage error naming the unknown token. This is the routing seam every
    /// dispatched command goes through.
    pub fn resolve(&self, group: &str, verb: &str) -> CliResult<&VerbDescriptor> {
        let group = self.group(group).ok_or_else(|| {
            CliError::usage(format!(
                "unknown command '{group}'; run --help for the command list"
            ))
        })?;
        group.verb(verb).ok_or_else(|| {
            CliError::usage(format!(
                "unknown verb '{verb}' for '{}'; run '{} --help'",
                group.name, group.name
            ))
        })
    }

    /// The set of OpenAPI `operationId`s the registered commands cover. The
    /// #365 parity gate diffs this against the contract's operation set.
    /// Returned sorted and de-duplicated for stable comparison.
    pub fn coverage_manifest(&self) -> BTreeSet<String> {
        self.groups
            .iter()
            .flat_map(|group| group.verbs.iter())
            .filter_map(|verb| verb.operation_id.clone())
            .collect()
    }

    /// A stable, human-readable help summary: one line per `group verb`.
    pub fn help_summary(&self) -> String {
        let mut lines = Vec::new();
        for group in &self.groups {
            for verb in &group.verbs {
                lines.push(format!("{} {:<10} {}", group.name, verb.name, verb.about));
            }
        }
        lines.join("\n")
    }
}

#[cfg(test)]
#[path = "command_test.rs"]
mod command_test;
