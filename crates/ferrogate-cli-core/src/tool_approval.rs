// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tool-approval workflow command family (issue #362).
//!
//! Exposes the human-in-the-loop tool-call approval surface of the Control Plane
//! API: the queue of pending tool calls (`list`/`get`) plus the three terminal
//! resolutions of a pending call — `approve`, `deny`, and `expire`. Each verb
//! declares the OpenAPI `operationId` it invokes as compile-time metadata (the
//! single source of truth the #365 parity gate diffs against the contract), and
//! a `build` function maps a resolved verb plus typed [`ResourceInput`] onto a
//! [`RequestSpec`] through the shared [`ResourceApi`] REST builders.
//!
//! The three resolutions are first-class lifecycle actions, not generic writes:
//! each is a `POST .../{approval_id}/{action}` sub-path so the operator's intent
//! and the resulting audit correlation are explicit. Approval is guarded
//! server-side by the tool call's immutable action fingerprint (the server
//! rejects the resolution if the fingerprint no longer matches), and the actor
//! evidence (who approved/denied, with what justification) rides the
//! operator-supplied JSON body — kept schema-agnostic here because the server
//! owns the evidence contract.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, build_item_action, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/tool-approvals` — the pending tool-call approval queue.
pub const TOOL_APPROVALS: ResourceApi = ResourceApi::new("/admin/v1/tool-approvals");

/// Tool approvals: the pending queue (read) plus the approve/deny/expire
/// lifecycle resolutions.
pub struct ToolApprovalsGroup;

impl CommandGroup for ToolApprovalsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tool-approvals",
            "Review and resolve pending tool-call approvals",
            vec![
                VerbDescriptor::read(
                    "list",
                    "List pending tool-call approvals",
                    "listAdminToolApprovals",
                ),
                VerbDescriptor::read("get", "Show a tool-call approval", "getAdminToolApproval"),
                VerbDescriptor::mutating(
                    "approve",
                    "Approve a pending tool call (fingerprint must still match)",
                    "approveAdminToolApproval",
                ),
                VerbDescriptor::mutating(
                    "deny",
                    "Deny a pending tool call",
                    "denyAdminToolApproval",
                ),
                VerbDescriptor::mutating(
                    "expire",
                    "Expire a pending tool call",
                    "expireAdminToolApproval",
                ),
            ],
        )
    }
}

/// Build the request for a tool-approvals verb.
///
/// `approve`/`deny`/`expire` each `POST` to the item's `.../{action}` sub-path,
/// carrying the optional actor-evidence body; `list`/`get` are plain reads.
pub fn build_tool_approvals(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "approve" => build_item_action(&TOOL_APPROVALS, "tool-approval", "approve", input),
        "deny" => build_item_action(&TOOL_APPROVALS, "tool-approval", "deny", input),
        "expire" => build_item_action(&TOOL_APPROVALS, "tool-approval", "expire", input),
        other => build_crud(&TOOL_APPROVALS, other, input),
    }
}

/// Register the tool-approval command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&ToolApprovalsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "tool_approval_test.rs"]
mod tool_approval_test;
