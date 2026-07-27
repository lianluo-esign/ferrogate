// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Evidence (request-log / audit / correlation) command families (issue #364).
//!
//! Exposes the investigation-friendly read and export surface of the Control
//! Plane API: retained request logs and their redacted JSONL export, retained
//! Admin API audit events, and observed agent activity (agent/run correlations).
//! Each resource noun is a [`CommandGroup`] declaring its verbs and OpenAPI
//! `operationId`s as compile-time metadata (tracked by the #365 parity gate),
//! plus a `build` function mapping a resolved verb and typed [`ResourceInput`]
//! onto a [`RequestSpec`] via the shared [`ResourceApi`] REST builders.
//!
//! ## Reads preserve pagination and filters
//!
//! Every verb here is a read: the operator's pagination and server-side filters
//! (organization/project/model/provider/status/time-window) flow through
//! unmodified via [`ResourceInput::list`], so a filtered investigation query is
//! reproduced exactly on the wire rather than being narrowed or re-derived
//! client-side.
//!
//! ## Export separates payload from diagnostics
//!
//! `request-logs export` maps to `GET /admin/v1/request-log-exports`, which
//! streams redacted JSONL. This layer only builds the request; the command layer
//! that consumes it routes the JSONL payload to stdout and keeps progress /
//! diagnostics on stderr (the [`crate::output`] contract), so the export stays
//! pipeable. The response carries `x-request-id` / `x-trace-id`, which
//! [`crate::transport::classify`] preserves for audit attribution.
//!
//! ## Excluded from this family (with reason)
//!
//! * `listAdminObservability` — the general observability snapshot is an
//!   operator-facing surface and is owned by the #364 `ops` family
//!   (`system observability`), not the evidence read surface.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/request-logs` — retained request logs (read view).
pub const REQUEST_LOGS: ResourceApi = ResourceApi::new("/admin/v1/request-logs");
/// `/admin/v1/request-log-exports` — redacted JSONL request-log export.
pub const REQUEST_LOG_EXPORTS: ResourceApi = ResourceApi::new("/admin/v1/request-log-exports");
/// `/admin/v1/audit-events` — retained Admin API audit events (read view).
pub const AUDIT_EVENTS: ResourceApi = ResourceApi::new("/admin/v1/audit-events");
/// `/admin/v1/observed-agent-activity` — observed agent/run correlations (read view).
pub const OBSERVED_AGENT_ACTIVITY: ResourceApi =
    ResourceApi::new("/admin/v1/observed-agent-activity");

/// Retained request logs: list and redacted JSONL export.
pub struct RequestLogsGroup;

impl CommandGroup for RequestLogsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "request-logs",
            "Inspect and export retained request logs",
            vec![
                VerbDescriptor::read("list", "List retained request logs", "listAdminRequestLogs"),
                VerbDescriptor::read(
                    "export",
                    "Export request logs as redacted JSONL",
                    "exportAdminRequestLogsJsonl",
                ),
            ],
        )
    }
}

/// Build the request for a `request-logs` verb. `export` reads the JSONL export
/// endpoint; `list` reads the retained-log collection. Both carry the operator's
/// filters/pagination through `input.list`.
pub fn build_request_logs(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "export" => REQUEST_LOG_EXPORTS.read(&[], &input.list),
        other => build_crud(&REQUEST_LOGS, other, input),
    }
}

/// Retained Admin API audit events (read-only list view).
pub struct AuditEventsGroup;

impl CommandGroup for AuditEventsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "audit-events",
            "List retained Admin API audit events",
            vec![VerbDescriptor::read(
                "list",
                "List audit events",
                "listAdminAuditEvents",
            )],
        )
    }
}

/// Build the request for an `audit-events` verb.
pub fn build_audit_events(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&AUDIT_EVENTS, verb, input)
}

/// Observed agent/run correlations (read-only list view).
pub struct ObservedAgentActivityGroup;

impl CommandGroup for ObservedAgentActivityGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "observed-agent-activity",
            "List observed agent/run activity correlations",
            vec![VerbDescriptor::read(
                "list",
                "List observed agent activity",
                "listAdminObservedAgentActivity",
            )],
        )
    }
}

/// Build the request for an `observed-agent-activity` verb.
pub fn build_observed_agent_activity(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&OBSERVED_AGENT_ACTIVITY, verb, input)
}

/// Register every evidence command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&RequestLogsGroup)?;
    registry.register(&AuditEventsGroup)?;
    registry.register(&ObservedAgentActivityGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "evidence_test.rs"]
mod evidence_test;
