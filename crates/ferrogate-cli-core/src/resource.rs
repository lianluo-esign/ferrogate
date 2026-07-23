// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Uniform REST request construction for declarative resource families
//! (issue #361).
//!
//! Every organization / IAM / policy / gateway-config resource on the Control
//! Plane API follows the same collection shape: `GET`/`POST` on a collection
//! path, `GET`/`PUT`/`PATCH`/`DELETE` on an item under it, plus the occasional
//! action sub-path (`.../{id}/rotate`) or nested sub-collection
//! (`.../{tenant_id}/{role_id}`). Rather than hand-write one URL per operation
//! — the exact hard-coding the #365 OpenAPI parity gate exists to reject — a
//! family declares its collection path once as a [`ResourceApi`] and derives
//! every verb's [`RequestSpec`] from typed path segments plus a
//! `serde_json::Value` document. The body stays schema-agnostic (the operator
//! supplies a complete JSON document per the command contract), so no
//! per-resource request struct is baked in here; the operation each verb maps
//! to is carried as `operationId` metadata on the [`crate::command::CommandGroup`]
//! descriptor, which is the single source of parity truth.
//!
//! Everything in this module is pure (no network, no clock), so a family's verb
//! → request mapping is unit-testable in isolation and, driven through a fake
//! [`crate::transport::Transport`], end to end.

use http::Method;
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::transport::{PageRequest, RequestSpec};

/// A single declarative resource collection on the Control Plane API.
///
/// Holds only the absolute collection path (e.g. `/admin/v1/tenant-accounts`);
/// item and action paths are derived from typed segments. Construct one `const`
/// per resource noun in the family module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceApi {
    collection: &'static str,
}

impl ResourceApi {
    /// Declare a collection. The path must be absolute and carry no trailing
    /// slash; that invariant is asserted in debug builds because it is a
    /// compile-time constant authored in this crate, not user input.
    pub const fn new(collection: &'static str) -> ResourceApi {
        ResourceApi { collection }
    }

    /// The collection path this resource lives under.
    pub fn collection_path(&self) -> &'static str {
        self.collection
    }

    /// Build the absolute path for zero or more trailing item segments,
    /// percent-encoding each so an id containing a reserved character can never
    /// smuggle extra path structure or a query string into the URL. An empty
    /// or whitespace-only segment is a usage error rather than a silently
    /// collapsed `//`.
    fn item_path(&self, segments: &[&str]) -> CliResult<String> {
        let mut path = self.collection.to_string();
        for segment in segments {
            if segment.trim().is_empty() {
                return Err(CliError::usage(format!(
                    "resource path segment for '{}' must not be empty",
                    self.collection
                )));
            }
            path.push('/');
            path.push_str(&encode_segment(segment));
        }
        Ok(path)
    }

    /// `GET` a collection or nested list. `segments` is empty for the top-level
    /// list; non-empty for a nested list such as tenant-role bindings under a
    /// tenant. Pagination and filter parameters from `params` are folded in.
    pub fn read(&self, segments: &[&str], params: &ListParams) -> CliResult<RequestSpec> {
        let mut spec = RequestSpec::new(Method::GET, self.item_path(segments)?);
        spec = params.apply(spec);
        Ok(spec)
    }

    /// A `GET` on the item identified by `segments`, with no query parameters.
    pub fn get(&self, segments: &[&str]) -> CliResult<RequestSpec> {
        self.read(segments, &ListParams::new())
    }

    /// The top-level collection listing.
    pub fn list(&self, params: &ListParams) -> CliResult<RequestSpec> {
        self.read(&[], params)
    }

    /// A body-carrying mutation (`POST`/`PUT`/`PATCH`) or a `DELETE`.
    ///
    /// `segments` selects the target (empty = the collection itself, for
    /// `create`). The body is a complete JSON document supplied by the operator
    /// for writes, or `None` for `DELETE` and body-less action calls.
    pub fn mutate(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<Value>,
    ) -> CliResult<RequestSpec> {
        let mut spec = RequestSpec::new(method, self.item_path(segments)?);
        if let Some(body) = body {
            spec = spec.with_json_body(body);
        }
        Ok(spec)
    }

    /// `POST` a new document to the collection.
    pub fn create(&self, body: Value) -> CliResult<RequestSpec> {
        self.mutate(Method::POST, &[], Some(body))
    }

    /// `PUT` a full replacement document over the item.
    pub fn replace(&self, segments: &[&str], body: Value) -> CliResult<RequestSpec> {
        self.mutate(Method::PUT, segments, Some(body))
    }

    /// `PATCH` a partial update over the item.
    pub fn update(&self, segments: &[&str], body: Value) -> CliResult<RequestSpec> {
        self.mutate(Method::PATCH, segments, Some(body))
    }

    /// `DELETE` the item.
    pub fn delete(&self, segments: &[&str]) -> CliResult<RequestSpec> {
        self.mutate(Method::DELETE, segments, None)
    }

    /// A `POST` action sub-path such as `.../{id}/rotate` or
    /// `.../{id}/disable`. `segments` includes both the item id and the action
    /// name so the caller declares the exact operation surface. `body` is
    /// optional because many lifecycle actions take no request document.
    pub fn action(&self, segments: &[&str], body: Option<Value>) -> CliResult<RequestSpec> {
        self.mutate(Method::POST, segments, body)
    }
}

/// Query parameters for a list request: optional pagination plus explicit
/// server-side filters. Filters are never inferred from local config — the
/// caller passes exactly what it wants sent — which keeps tenant/resource
/// targeting auditable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListParams {
    page: Option<PageRequest>,
    filters: Vec<(String, String)>,
}

impl ListParams {
    /// No pagination and no filters (server defaults apply).
    pub fn new() -> ListParams {
        ListParams::default()
    }

    /// Request a specific page.
    pub fn with_page(mut self, page: PageRequest) -> ListParams {
        self.page = Some(page);
        self
    }

    /// Add a server-side filter parameter.
    pub fn with_filter(mut self, key: impl Into<String>, value: impl Into<String>) -> ListParams {
        self.filters.push((key.into(), value.into()));
        self
    }

    /// Fold pagination and filters into a request spec.
    fn apply(&self, mut spec: RequestSpec) -> RequestSpec {
        if let Some(page) = &self.page {
            spec = spec.with_page(page);
        }
        for (key, value) in &self.filters {
            spec = spec.with_query(key.clone(), value.clone());
        }
        spec
    }
}

/// Percent-encode one path segment, preserving RFC 3986 unreserved characters
/// (`ALPHA` / `DIGIT` / `-` / `.` / `_` / `~`) and encoding everything else.
/// This is deliberately stricter than query encoding: a `/` in an id becomes
/// `%2F` so it cannot extend the path.
pub fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Redact named secret fields in a decoded API response so key material never
/// reaches `list`/`get` rendering. Recurses into arrays and objects, replacing
/// any matching field's value with a fixed `"<redacted>"` marker. A one-time
/// secret returned at create/rotate is thus visible only at the moment of that
/// call (where the command layer routes it to a safe sink), never in a later
/// read of the same resource.
pub fn redact_secret_fields(value: &mut Value, secret_fields: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, field) in map.iter_mut() {
                if secret_fields.contains(&key.as_str()) && !field.is_null() {
                    *field = Value::String("<redacted>".to_string());
                } else {
                    redact_secret_fields(field, secret_fields);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_secret_fields(item, secret_fields);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "resource_test.rs"]
mod resource_test;
