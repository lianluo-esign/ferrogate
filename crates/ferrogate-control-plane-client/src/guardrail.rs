// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Guardrail governance command families (issue #362).
//!
//! Exposes the guardrail-policy governance surface of the Control Plane API,
//! modelled as three resource nouns:
//!
//! * **guardrail-policies** — the immutable-revision policy store. A policy is a
//!   chain of append-only revisions: `create` opens a new policy chain and
//!   `create-revision` appends the next revision, while `get`/`revisions`/
//!   `get-revision` read the chain and `archive` retires one revision. Because
//!   revisions are immutable, promotion is a lifecycle action, not a mutation:
//!   `activate` promotes a revision to live, `rollback` atomically returns to an
//!   archived revision, and `dry-run` selects and inspects a revision without
//!   dispatching any model provider, external detector, or action.
//! * **guardrail-evaluations** — the read-only evaluation event stream.
//! * **investigations** — the cross-evidence join that correlates identity,
//!   route, policy, guardrail, approval, execution, usage, cost, and outcome
//!   evidence for one `request_id`/`trace_id`/`agent_run_id` (passed as list
//!   filters).
//!
//! Each verb declares the OpenAPI `operationId` it invokes as compile-time
//! metadata (the single source of truth the #365 parity gate diffs against the
//! contract), and a `build` function maps a resolved verb plus typed
//! [`ResourceInput`] onto a [`RequestSpec`] through the shared [`ResourceApi`]
//! REST builders. Bodies stay schema-agnostic: the operator supplies a complete
//! JSON document (a revision definition, or the activate/rollback/dry-run
//! selector) and the server owns its schema.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::{CliError, CliResult};
use crate::registry_helpers::{build_crud, build_item_action, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/guardrail-policies` — the immutable-revision guardrail policy store.
pub const GUARDRAIL_POLICIES: ResourceApi = ResourceApi::new("/admin/v1/guardrail-policies");
/// `/admin/v1/guardrail-evaluations` — the read-only evaluation event stream.
pub const GUARDRAIL_EVALUATIONS: ResourceApi = ResourceApi::new("/admin/v1/guardrail-evaluations");
/// `/admin/v1/investigations` — the cross-evidence correlation join.
pub const INVESTIGATIONS: ResourceApi = ResourceApi::new("/admin/v1/investigations");

/// The `{policy_id}` and `{revision}` a revision-scoped verb addresses, or a
/// usage error naming the missing segment.
fn policy_and_revision(input: &ResourceInput) -> CliResult<(&str, &str)> {
    let policy = first_segment(input, "guardrail-policy")?;
    let revision = input
        .segments
        .get(1)
        .map(String::as_str)
        .filter(|segment| !segment.trim().is_empty())
        .ok_or_else(|| {
            CliError::usage(
                "this guardrail-policy verb requires a revision id as its second argument",
            )
        })?;
    Ok((policy, revision))
}

/// Guardrail policies: immutable-revision CRUD plus the activate/rollback/dry-run
/// promotion lifecycle and the nested revision sub-collection.
pub struct GuardrailPoliciesGroup;

impl CommandGroup for GuardrailPoliciesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "guardrail-policies",
            "Manage guardrail policies and their immutable revisions",
            vec![
                VerbDescriptor::read(
                    "list",
                    "List guardrail policies",
                    "listGuardrailPolicyRevisions",
                ),
                VerbDescriptor::mutating(
                    "create",
                    "Create a guardrail policy (first revision)",
                    "createGuardrailPolicyRevision",
                ),
                VerbDescriptor::read(
                    "get",
                    "List one policy's immutable revisions",
                    "listGuardrailPolicyRevisionsByPolicy",
                ),
                VerbDescriptor::read(
                    "revisions",
                    "List a policy's revision history",
                    "listGuardrailPolicyRevisionHistory",
                ),
                VerbDescriptor::mutating(
                    "create-revision",
                    "Append the next revision to a policy",
                    "createNextGuardrailPolicyRevision",
                ),
                VerbDescriptor::read(
                    "get-revision",
                    "Show one immutable policy revision",
                    "getGuardrailPolicyRevision",
                ),
                VerbDescriptor::mutating(
                    "archive",
                    "Archive one immutable policy revision",
                    "archiveGuardrailPolicyRevision",
                )
                .without_request_body(),
                VerbDescriptor::mutating(
                    "activate",
                    "Activate a policy revision (make it live)",
                    "activateGuardrailPolicyRevision",
                ),
                VerbDescriptor::mutating(
                    "rollback",
                    "Roll back to an archived policy revision",
                    "rollbackGuardrailPolicyRevision",
                ),
                VerbDescriptor::mutating(
                    "dry-run",
                    "Inspect a revision without dispatching detectors or actions",
                    "dryRunGuardrailPolicyRevision",
                ),
            ],
        )
    }
}

/// Build the request for a guardrail-policies verb.
///
/// The revision sub-collection (`revisions`/`create-revision`) and a single
/// revision (`get-revision`/`archive`) address nested paths; the promotion
/// actions (`activate`/`rollback`/`dry-run`) `POST` to the policy's action
/// sub-path; `list`/`create` are plain collection CRUD.
pub fn build_guardrail_policies(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "get" => GUARDRAIL_POLICIES.get(&[first_segment(input, "guardrail-policy")?]),
        "revisions" => GUARDRAIL_POLICIES.read(
            &[first_segment(input, "guardrail-policy")?, "revisions"],
            &input.list,
        ),
        "create-revision" => GUARDRAIL_POLICIES.action(
            &[first_segment(input, "guardrail-policy")?, "revisions"],
            Some(input.require_body(verb)?),
        ),
        "get-revision" => {
            let (policy, revision) = policy_and_revision(input)?;
            GUARDRAIL_POLICIES.get(&[policy, "revisions", revision])
        }
        "archive" => {
            let (policy, revision) = policy_and_revision(input)?;
            GUARDRAIL_POLICIES.delete(&[policy, "revisions", revision])
        }
        "activate" => build_item_action(&GUARDRAIL_POLICIES, "guardrail-policy", "activate", input),
        "rollback" => build_item_action(&GUARDRAIL_POLICIES, "guardrail-policy", "rollback", input),
        "dry-run" => build_item_action(&GUARDRAIL_POLICIES, "guardrail-policy", "dry-run", input),
        other => build_crud(&GUARDRAIL_POLICIES, other, input),
    }
}

/// Guardrail evaluations (read-only event stream).
pub struct GuardrailEvaluationsGroup;

impl CommandGroup for GuardrailEvaluationsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "guardrail-evaluations",
            "Inspect the guardrail evaluation event stream",
            vec![VerbDescriptor::read(
                "list",
                "List guardrail evaluations",
                "listGuardrailEvaluations",
            )],
        )
    }
}

/// Build the request for a guardrail-evaluations verb.
pub fn build_guardrail_evaluations(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&GUARDRAIL_EVALUATIONS, verb, input)
}

/// Investigations: the cross-evidence correlation join for one request/trace/run.
pub struct InvestigationsGroup;

impl CommandGroup for InvestigationsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "investigations",
            "Join cross-plane evidence for one request, trace, or agent run",
            vec![VerbDescriptor::read(
                "get",
                "Join evidence for a request_id/trace_id/agent_run_id",
                "getGuardrailInvestigation",
            )],
        )
    }
}

/// Build the request for an investigations verb. The join is a collection-level
/// read keyed entirely by `request_id`/`trace_id`/`agent_run_id` list filters.
pub fn build_investigations(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "get" => INVESTIGATIONS.read(&[], &input.list),
        other => build_crud(&INVESTIGATIONS, other, input),
    }
}

/// Register every guardrail command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&GuardrailPoliciesGroup)?;
    registry.register(&GuardrailEvaluationsGroup)?;
    registry.register(&InvestigationsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "guardrail_test.rs"]
mod guardrail_test;
