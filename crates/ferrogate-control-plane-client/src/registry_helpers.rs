// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Shared verb-dispatch helpers for resource command families (issue #361).
//!
//! A family's `build` function receives a resolved verb name (already gated by
//! the [`crate::command::Registry`] against the family's declared verbs) plus a
//! [`ResourceInput`] carrying the typed pieces a command line supplies — the id
//! path segments, an optional complete JSON body for writes, and list
//! pagination/filters. [`build_crud`] maps the six uniform CRUD verbs onto the
//! shared [`ResourceApi`] REST builders; families layer their action verbs
//! (rotate, disable, bind, …) on top before delegating here. Keeping the CRUD
//! mapping in one place means the `verb → HTTP method + path` contract cannot
//! drift between families.

use http::Method;
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::resource::{ListParams, ResourceApi};
use crate::transport::RequestSpec;

/// The typed inputs a resolved command contributes to request construction.
///
/// This is intentionally framework-neutral: the Clap layer (a later slice)
/// populates it, but every field can also be built directly in a unit test, so
/// the verb → request mapping is provable without a parser or a network.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourceInput {
    /// Path segments identifying the target (e.g. `[tenant_id]`, or
    /// `[scope_type, scope_id]` for a composite key). Empty for a collection
    /// operation such as `list`/`create`.
    pub segments: Vec<String>,
    /// A complete JSON document for a mutation. Required by write verbs; the
    /// server owns the schema, so it is carried opaquely.
    pub body: Option<Value>,
    /// Pagination and server-side filters for list verbs.
    pub list: ListParams,
}

impl ResourceInput {
    /// An empty input (collection list with no filters).
    pub fn new() -> ResourceInput {
        ResourceInput::default()
    }

    /// Target a specific item by one or more id segments.
    pub fn with_segments<I, S>(mut self, segments: I) -> ResourceInput
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.segments = segments.into_iter().map(Into::into).collect();
        self
    }

    /// Attach a mutation body document.
    pub fn with_body(mut self, body: Value) -> ResourceInput {
        self.body = Some(body);
        self
    }

    /// Attach list pagination/filters.
    pub fn with_list(mut self, list: ListParams) -> ResourceInput {
        self.list = list;
        self
    }

    /// Borrow the id segments as `&str` for the REST builders.
    pub fn segment_refs(&self) -> Vec<&str> {
        self.segments.iter().map(String::as_str).collect()
    }

    /// The body a write verb requires, or an actionable usage error naming the
    /// verb so the operator knows a `--file`/stdin document was expected.
    pub fn require_body(&self, verb: &str) -> CliResult<Value> {
        self.body.clone().ok_or_else(|| {
            CliError::usage(format!(
                "verb '{verb}' requires a JSON request document (provide one via --file or stdin)"
            ))
        })
    }
}

/// The first id segment, or a usage error naming the resource. Used by action
/// verbs that address a single item (e.g. `virtual-keys rotate <id>`).
pub fn first_segment<'a>(input: &'a ResourceInput, resource: &str) -> CliResult<&'a str> {
    input
        .segments
        .first()
        .map(String::as_str)
        .filter(|segment| !segment.trim().is_empty())
        .ok_or_else(|| CliError::usage(format!("this {resource} verb requires a target id")))
}

/// Reject a target verb that was not given its complete key.
///
/// `item_path(&[])` loops zero times and returns the BARE COLLECTION path, and
/// the clap positional `segments: Vec<String>` carries no arity requirement, so
/// omitting the id was accepted and silently retargeted the whole collection:
///
/// * `ferrogate ctl projects get` issued `GET /admin/v1/projects` -- the LIST
///   operation, from a verb whose declared operationId is `getProject`, exiting
///   0 with the entire collection on stdout. That made the parity mapping true
///   in metadata and false at runtime.
/// * `ferrogate ctl projects delete` issued a collection-level
///   `DELETE /admin/v1/projects`, with no client-side guard whatsoever.
///
/// Single-key CRUD uses one segment; composite resources state the complete
/// count through [`build_crud_with_item_segments`]. Action verbs may call this
/// directly when their target is not a single id.
///
/// `list` is deliberately NOT guarded: an empty segment list IS the top-level
/// collection read, and a non-empty one is a nested list (e.g. tenant-role
/// bindings under a tenant). `create` addresses the collection by definition.
pub(crate) fn require_target_segments<'a>(
    api: &ResourceApi,
    verb: &str,
    segments: &'a [&'a str],
    required: usize,
) -> CliResult<&'a [&'a str]> {
    assert!(required > 0, "target verbs require at least one segment");
    if segments.len() < required
        || segments
            .iter()
            .take(required)
            .any(|segment| segment.trim().is_empty())
    {
        let requirement = if required == 1 {
            "a target id".to_string()
        } else {
            format!("{required} non-empty target segments")
        };
        return Err(CliError::usage(format!(
            "verb '{verb}' requires {requirement} under {}; received {} segment(s)",
            api.collection_path(),
            segments.len()
        )));
    }
    Ok(segments)
}

/// Map one of the six uniform CRUD verbs onto a request against `api`.
///
/// Returns a usage error for an unrecognized verb; in normal dispatch the
/// registry has already validated the verb against the family descriptor, so
/// this arm only fires for a family that declared a verb it did not wire.
pub fn build_crud(api: &ResourceApi, verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud_with_item_segments(api, verb, input, 1)
}

/// Map uniform CRUD verbs while requiring the complete item key for item
/// operations. Composite-key resources use this instead of silently accepting
/// the first segment as a complete key.
pub fn build_crud_with_item_segments(
    api: &ResourceApi,
    verb: &str,
    input: &ResourceInput,
    required_item_segments: usize,
) -> CliResult<RequestSpec> {
    let segments = input.segment_refs();
    match verb {
        "list" => api.read(&segments, &input.list),
        "get" => api.get(require_target_segments(
            api,
            verb,
            &segments,
            required_item_segments,
        )?),
        "create" => api.create(input.require_body(verb)?),
        "replace" => api.replace(
            require_target_segments(api, verb, &segments, required_item_segments)?,
            input.require_body(verb)?,
        ),
        "update" => api.update(
            require_target_segments(api, verb, &segments, required_item_segments)?,
            input.require_body(verb)?,
        ),
        "delete" => api.delete(require_target_segments(
            api,
            verb,
            &segments,
            required_item_segments,
        )?),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not a standard CRUD verb for {}",
            api.collection_path()
        ))),
    }
}

/// Map a `POST` lifecycle action verb onto `.../{id}/{action}` against `api`,
/// taking the target id from the first input segment and an optional body.
pub fn build_item_action(
    api: &ResourceApi,
    resource: &str,
    action: &str,
    input: &ResourceInput,
) -> CliResult<RequestSpec> {
    let id = first_segment(input, resource)?;
    api.action(&[id, action], input.body.clone())
}

/// Map a `DELETE` lifecycle verb (e.g. virtual-key revoke) onto the item.
pub fn build_item_delete(
    api: &ResourceApi,
    resource: &str,
    input: &ResourceInput,
) -> CliResult<RequestSpec> {
    let id = first_segment(input, resource)?;
    api.mutate(Method::DELETE, &[id], None)
}

#[cfg(test)]
#[path = "registry_helpers_test.rs"]
mod registry_helpers_test;
