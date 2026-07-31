// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Agent lifecycle command families (issue #362).
//!
//! Exposes the agent-native control surface of the Control Plane API: agent
//! workflows and upstreams (declarative CRUD), agent schedules (CRUD plus the
//! `run-now` lifecycle action and the read-only fire history), and agent runs
//! (start a run, list runs, read a run timeline). As with the #361 families,
//! each resource noun is a [`CommandGroup`] that declares its verbs and the
//! OpenAPI `operationId` each verb invokes as compile-time metadata — the single
//! source of truth the #365 parity gate diffs against the contract — and a
//! `build` function that maps a resolved verb plus typed [`ResourceInput`] onto
//! a [`RequestSpec`] through the shared [`ResourceApi`] REST builders. No request
//! body schema is hard-coded: mutations and run-start carry a complete
//! operator-supplied JSON document.
//!
//! Non-trivial actions are first-class, not generic CRUD:
//!
//! * A schedule's `run-now` is a `POST .../{id}/run-now` action so the operator's
//!   intent (and the resulting run/audit correlation) is precise, and `fires`
//!   reads the immutable fire history rather than reconstructing it client-side.
//! * `agent-runs start` submits typed intent to the runtime `POST /v1/agent-runs`
//!   operation; the server owns run admission, so the CLI reports its decision.
//!
//! Explicitly excluded from this family (data-plane / discovery surfaces a
//! management CLI does not drive): `invokeAgent`, `sendAgentMessage`,
//! `streamAgentMessage`, `getAgentDiscovery`, `listAgentSkills`, `getAgentSkill`,
//! and `listAdminObservedAgentActivity` (deferred observability view).

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, build_item_action, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/agent-workflows` — declarative agent workflow definitions.
pub const AGENT_WORKFLOWS: ResourceApi = ResourceApi::new("/admin/v1/agent-workflows");
/// `/admin/v1/agent-schedules` — agent run schedules.
pub const AGENT_SCHEDULES: ResourceApi = ResourceApi::new("/admin/v1/agent-schedules");
/// `/admin/v1/agent-upstreams` — agent upstream/provider bindings.
pub const AGENT_UPSTREAMS: ResourceApi = ResourceApi::new("/admin/v1/agent-upstreams");
/// `/admin/v1/agent-runs` — the admin view of agent runs (list + timeline).
pub const AGENT_RUNS: ResourceApi = ResourceApi::new("/admin/v1/agent-runs");
/// `/v1/agent-runs` — the runtime run-start operation (`createAgentRun`).
pub const AGENT_RUNS_RUNTIME: ResourceApi = ResourceApi::new("/v1/agent-runs");
/// `/v1/agent-jobs` — the async long-running job protocol (#474): submit a job,
/// observe it, collect its result, cancel it.
pub const AGENT_JOBS: ResourceApi = ResourceApi::new("/v1/agent-jobs");

/// Agent workflows (full CRUD).
pub struct AgentWorkflowsGroup;

impl CommandGroup for AgentWorkflowsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "agent-workflows",
            "Manage agent workflow definitions",
            vec![
                VerbDescriptor::read("list", "List agent workflows", "listAdminAgentWorkflows"),
                VerbDescriptor::read("get", "Show an agent workflow", "getAdminAgentWorkflow"),
                VerbDescriptor::mutating(
                    "create",
                    "Create an agent workflow",
                    "createAdminAgentWorkflow",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace an agent workflow",
                    "putAdminAgentWorkflow",
                )
                .replacing_whole_document(),
                VerbDescriptor::mutating(
                    "update",
                    "Update an agent workflow",
                    "patchAdminAgentWorkflow",
                ),
                VerbDescriptor::mutating(
                    "delete",
                    "Delete an agent workflow",
                    "deleteAdminAgentWorkflow",
                )
                .without_request_body(),
            ],
        )
    }
}

/// Build the request for an agent-workflows verb.
pub fn build_agent_workflows(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&AGENT_WORKFLOWS, verb, input)
}

/// Agent schedules (CRUD plus the `run-now` action and `fires` history).
pub struct AgentSchedulesGroup;

impl CommandGroup for AgentSchedulesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "agent-schedules",
            "Manage agent run schedules and their fire history",
            vec![
                VerbDescriptor::read("list", "List agent schedules", "listAdminAgentSchedules"),
                VerbDescriptor::read("get", "Show an agent schedule", "getAdminAgentSchedule"),
                VerbDescriptor::mutating(
                    "create",
                    "Create an agent schedule",
                    "createAdminAgentSchedule",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace an agent schedule",
                    "putAdminAgentSchedule",
                )
                .replacing_whole_document(),
                VerbDescriptor::mutating(
                    "update",
                    "Update an agent schedule",
                    "patchAdminAgentSchedule",
                ),
                VerbDescriptor::mutating(
                    "delete",
                    "Delete an agent schedule",
                    "deleteAdminAgentSchedule",
                )
                .without_request_body(),
                VerbDescriptor::mutating(
                    "run-now",
                    "Trigger a schedule to run immediately",
                    "runAdminAgentScheduleNow",
                ),
                VerbDescriptor::read(
                    "fires",
                    "List a schedule's fire history",
                    "listAdminAgentScheduleFires",
                ),
            ],
        )
    }
}

/// Build the request for an agent-schedules verb. The lifecycle action and the
/// nested fire-history read map to their own sub-paths; everything else is CRUD.
pub fn build_agent_schedules(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "run-now" => build_item_action(&AGENT_SCHEDULES, "agent-schedule", "run-now", input),
        "fires" => AGENT_SCHEDULES.read(
            &[first_segment(input, "agent-schedule")?, "fires"],
            &input.list,
        ),
        other => build_crud(&AGENT_SCHEDULES, other, input),
    }
}

/// Agent upstreams (full CRUD).
pub struct AgentUpstreamsGroup;

impl CommandGroup for AgentUpstreamsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "agent-upstreams",
            "Manage agent upstream bindings",
            vec![
                VerbDescriptor::read("list", "List agent upstreams", "listAdminAgentUpstreams"),
                VerbDescriptor::read("get", "Show an agent upstream", "getAdminAgentUpstream"),
                VerbDescriptor::mutating(
                    "create",
                    "Create an agent upstream",
                    "createAdminAgentUpstream",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace an agent upstream",
                    "putAdminAgentUpstream",
                )
                .replacing_whole_document(),
                VerbDescriptor::mutating(
                    "update",
                    "Update an agent upstream",
                    "patchAdminAgentUpstream",
                ),
                VerbDescriptor::mutating(
                    "delete",
                    "Delete an agent upstream",
                    "deleteAdminAgentUpstream",
                )
                .without_request_body(),
            ],
        )
    }
}

/// Build the request for an agent-upstreams verb.
pub fn build_agent_upstreams(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&AGENT_UPSTREAMS, verb, input)
}

/// Agent runs: start a run (runtime), list runs, and read a run timeline (admin).
pub struct AgentRunsGroup;

impl CommandGroup for AgentRunsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "agent-runs",
            "Start and inspect agent runs",
            vec![
                VerbDescriptor::read("list", "List agent runs", "listAdminAgentRuns"),
                VerbDescriptor::read(
                    "get",
                    "Show an agent run timeline",
                    "getAdminAgentRunTimeline",
                ),
                VerbDescriptor::mutating("start", "Start an agent run", "createAgentRun"),
            ],
        )
    }
}

/// Build the request for an agent-runs verb.
///
/// `start` posts a complete run document to the runtime `POST /v1/agent-runs`;
/// `list`/`get` address the admin timeline view under `/admin/v1/agent-runs`.
pub fn build_agent_runs(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "start" => AGENT_RUNS_RUNTIME.create(input.require_body(verb)?),
        other => build_crud(&AGENT_RUNS, other, input),
    }
}

/// Async long-running agent jobs (#474): the caller-facing
/// submit → observe → collect → cancel protocol on `/v1/agent-jobs`.
///
/// Distinct from `agent-runs start`, which drives the *bounded* harness inside
/// the request: `submit` returns a durable `run_id` immediately and the
/// remaining verbs address that id.
pub struct AgentJobsGroup;

impl CommandGroup for AgentJobsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "agent-jobs",
            "Submit, observe, collect, and cancel long-running agent jobs",
            vec![
                VerbDescriptor::mutating(
                    "submit",
                    "Submit a long-running agent job (idempotent on the submitted idempotency_key)",
                    "submitAgentJob",
                ),
                VerbDescriptor::read("get", "Show an agent job's status", "getAgentJob"),
                VerbDescriptor::read(
                    "events",
                    "Read an agent job's incremental timeline events",
                    "listAgentJobEvents",
                ),
                VerbDescriptor::read(
                    "result",
                    "Collect a terminal agent job's result",
                    "getAgentJobResult",
                ),
                VerbDescriptor::mutating(
                    "cancel",
                    "Cancel an in-flight agent job",
                    "cancelAgentJob",
                ),
            ],
        )
    }
}

/// Build the request for an agent-jobs verb.
///
/// `submit` posts the job document to the collection; `get` addresses the job
/// by id; `events`/`result` are nested reads under it; `cancel` is a `POST`
/// lifecycle action, so the operator's intent (and the resulting audit record)
/// is precise rather than a generic mutation.
pub fn build_agent_jobs(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "submit" => AGENT_JOBS.create(input.require_body(verb)?),
        "get" => AGENT_JOBS.get(&[first_segment(input, "agent-job")?]),
        "events" => AGENT_JOBS.read(&[first_segment(input, "agent-job")?, "events"], &input.list),
        "result" => AGENT_JOBS.get(&[first_segment(input, "agent-job")?, "result"]),
        "cancel" => build_item_action(&AGENT_JOBS, "agent-job", "cancel", input),
        other => Err(crate::error::CliError::usage(format!(
            "verb '{other}' is not an agent-jobs verb"
        ))),
    }
}

/// Register every agent command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&AgentWorkflowsGroup)?;
    registry.register(&AgentSchedulesGroup)?;
    registry.register(&AgentUpstreamsGroup)?;
    registry.register(&AgentRunsGroup)?;
    registry.register(&AgentJobsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "agent_test.rs"]
mod agent_test;
