// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker lifecycle command families (issue #362).
//!
//! Covers the admin worker-fleet surface of the Control Plane API: self-hosted
//! workers (registration, identity rotation, telemetry events, checkpoints and
//! artifacts), the managed worker/session read views, the immutable
//! self-hosted-worker record view, and self-hosted run timelines. Each resource
//! noun is a [`CommandGroup`] declaring its verbs and OpenAPI `operationId`s as
//! compile-time metadata, plus a `build` function mapping a resolved verb onto a
//! [`RequestSpec`] via the shared [`ResourceApi`] REST builders.
//!
//! Worker lifecycle is modelled as first-class actions, not generic CRUD, so the
//! audit trail carries precise operator intent:
//!
//! * `register` creates a worker; `rotate` rotates its identity/certificate via
//!   `POST .../{id}/rotate`; `heartbeat`, `record-event`, `checkpoint`, and
//!   `artifact` submit typed evidence to their own action sub-paths.
//! * `events` reads the immutable telemetry stream rather than reconstructing it.
//!
//! The CLI drives the **admin** (`/admin/v1/...`) surface only. The worker
//! agent's own data-plane operations (`recordSelfHostedWorkerHeartbeat`,
//! `recordSelfHostedWorkerEvent`, `uploadSelfHostedWorkerArtifact`,
//! `uploadSelfHostedWorkerCheckpoint`, `pollSelfHostedWorkerRun`,
//! `acknowledgeSelfHostedWorkerRun`) and the ambiguous `registerAdminSelfHostedWorker`
//! (`POST /admin/v1/status`) are explicitly excluded — they are not management
//! actions an operator invokes from this client.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, build_item_action, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/self-hosted-workers` — self-hosted worker fleet.
pub const SELF_HOSTED_WORKERS: ResourceApi = ResourceApi::new("/admin/v1/self-hosted-workers");
/// `/admin/v1/managed-workers` — managed worker pools (read view).
pub const MANAGED_WORKERS: ResourceApi = ResourceApi::new("/admin/v1/managed-workers");
/// `/admin/v1/managed-worker-sessions` — managed worker sessions (read view).
pub const MANAGED_WORKER_SESSIONS: ResourceApi =
    ResourceApi::new("/admin/v1/managed-worker-sessions");
/// `/admin/v1/self-hosted-worker-records` — immutable worker records (read view).
pub const SELF_HOSTED_WORKER_RECORDS: ResourceApi =
    ResourceApi::new("/admin/v1/self-hosted-worker-records");
/// `/admin/v1/self-hosted-runs` — self-hosted run timelines (read view).
pub const SELF_HOSTED_RUNS: ResourceApi = ResourceApi::new("/admin/v1/self-hosted-runs");

/// Self-hosted workers, including registration and identity/telemetry lifecycle.
pub struct SelfHostedWorkersGroup;

impl CommandGroup for SelfHostedWorkersGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "self-hosted-workers",
            "Manage self-hosted workers and their lifecycle",
            vec![
                VerbDescriptor::api(
                    "list",
                    "List self-hosted workers",
                    "listAdminSelfHostedWorkers",
                ),
                VerbDescriptor::api(
                    "get",
                    "Show a self-hosted worker",
                    "getAdminSelfHostedWorker",
                ),
                VerbDescriptor::api(
                    "register",
                    "Register a self-hosted worker",
                    "registerSelfHostedWorker",
                ),
                VerbDescriptor::api(
                    "rotate",
                    "Rotate a worker's identity/certificate",
                    "rotateAdminSelfHostedWorkerIdentity",
                ),
                VerbDescriptor::api(
                    "heartbeat",
                    "Record a worker heartbeat",
                    "recordAdminSelfHostedWorkerHeartbeat",
                ),
                VerbDescriptor::api(
                    "events",
                    "List a worker's telemetry events",
                    "listAdminSelfHostedWorkerTelemetryEvents",
                ),
                VerbDescriptor::api(
                    "record-event",
                    "Record a worker telemetry event",
                    "recordAdminSelfHostedWorkerTelemetryEvent",
                ),
                VerbDescriptor::api(
                    "checkpoint",
                    "Record a worker checkpoint",
                    "recordAdminSelfHostedWorkerCheckpoint",
                ),
                VerbDescriptor::api(
                    "artifact",
                    "Record a worker artifact",
                    "recordAdminSelfHostedWorkerArtifact",
                ),
            ],
        )
    }
}

/// Build the request for a self-hosted-workers verb. Registration is a create on
/// the collection; the lifecycle actions map to their own sub-paths; `events`
/// reads the nested telemetry stream.
pub fn build_self_hosted_workers(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "register" => SELF_HOSTED_WORKERS.create(input.require_body(verb)?),
        "rotate" => build_item_action(&SELF_HOSTED_WORKERS, "self-hosted-worker", "rotate", input),
        "heartbeat" => build_item_action(
            &SELF_HOSTED_WORKERS,
            "self-hosted-worker",
            "heartbeat",
            input,
        ),
        "record-event" => {
            build_item_action(&SELF_HOSTED_WORKERS, "self-hosted-worker", "events", input)
        }
        "checkpoint" => build_item_action(
            &SELF_HOSTED_WORKERS,
            "self-hosted-worker",
            "checkpoints",
            input,
        ),
        "artifact" => build_item_action(
            &SELF_HOSTED_WORKERS,
            "self-hosted-worker",
            "artifacts",
            input,
        ),
        "events" => SELF_HOSTED_WORKERS.read(
            &[first_segment(input, "self-hosted-worker")?, "events"],
            &input.list,
        ),
        other => build_crud(&SELF_HOSTED_WORKERS, other, input),
    }
}

/// Managed workers (read-only list view).
pub struct ManagedWorkersGroup;

impl CommandGroup for ManagedWorkersGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "managed-workers",
            "List managed worker pools",
            vec![VerbDescriptor::api(
                "list",
                "List managed workers",
                "listAdminManagedWorkers",
            )],
        )
    }
}

/// Build the request for a managed-workers verb.
pub fn build_managed_workers(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&MANAGED_WORKERS, verb, input)
}

/// Managed worker sessions (read-only list view).
pub struct ManagedWorkerSessionsGroup;

impl CommandGroup for ManagedWorkerSessionsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "managed-worker-sessions",
            "List managed worker sessions",
            vec![VerbDescriptor::api(
                "list",
                "List managed worker sessions",
                "listAdminManagedWorkerSessions",
            )],
        )
    }
}

/// Build the request for a managed-worker-sessions verb.
pub fn build_managed_worker_sessions(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&MANAGED_WORKER_SESSIONS, verb, input)
}

/// Immutable self-hosted worker records (read-only list view).
pub struct SelfHostedWorkerRecordsGroup;

impl CommandGroup for SelfHostedWorkerRecordsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "self-hosted-worker-records",
            "List immutable self-hosted worker records",
            vec![VerbDescriptor::api(
                "list",
                "List self-hosted worker records",
                "listAdminSelfHostedWorkerRecords",
            )],
        )
    }
}

/// Build the request for a self-hosted-worker-records verb.
pub fn build_self_hosted_worker_records(
    verb: &str,
    input: &ResourceInput,
) -> CliResult<RequestSpec> {
    build_crud(&SELF_HOSTED_WORKER_RECORDS, verb, input)
}

/// Self-hosted run timelines (read-only get view).
pub struct SelfHostedRunsGroup;

impl CommandGroup for SelfHostedRunsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "self-hosted-runs",
            "Inspect self-hosted run timelines",
            vec![VerbDescriptor::api(
                "get",
                "Show a self-hosted run timeline",
                "getAdminSelfHostedRunTimeline",
            )],
        )
    }
}

/// Build the request for a self-hosted-runs verb.
pub fn build_self_hosted_runs(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&SELF_HOSTED_RUNS, verb, input)
}

/// Register every worker command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&SelfHostedWorkersGroup)?;
    registry.register(&ManagedWorkersGroup)?;
    registry.register(&ManagedWorkerSessionsGroup)?;
    registry.register(&SelfHostedWorkerRecordsGroup)?;
    registry.register(&SelfHostedRunsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "worker_test.rs"]
mod worker_test;
