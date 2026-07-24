// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! OpenAPI-to-CLI parity report (issue #365, coverage-manifest slice).
//!
//! The problem this solves: the `ferrogate` client must eventually cover every
//! operator-facing Control Plane API operation. Nothing stops the OpenAPI
//! contract from growing a new operation while the CLI silently fails to bind a
//! verb to it — a coverage gap no compiler catches. This module turns that
//! into a machine-checkable gate:
//!
//! 1. [`parse_openapi_surface`] enumerates the *coverable public surface* of
//!    `docs/openapi/admin-api.openapi.json` — every operation whose
//!    `x-ferrogate-contract.visibility` is `public` or `admin`. `internal`
//!    operations (gateway-internal self-hosted-worker plumbing, metrics
//!    scrape) are deliberately excluded: they are not operator commands, so a
//!    CLI verb for them would be wrong, not missing. This mirrors the
//!    visibility taxonomy `scripts/check-openapi.py` /
//!    `scripts/openapi_contract.py` enforce on the same document.
//!
//!    Runtime **data-plane** operations are excluded on a second axis. The
//!    OpenAI-compatible inference and MCP/tool-execution endpoints
//!    (`createChatCompletion`, `executeTool`, `mcpJsonRpc`, …) and the
//!    agent-runtime invoke/messaging endpoints (`invokeAgent`,
//!    `sendAgentMessage`, `streamAgentMessage`) are publicly reachable — their
//!    HTTP `visibility` is legitimately `public` — but they *move AI traffic*
//!    rather than *manage Control-Plane configuration*. A management CLI verb
//!    for live inference or agent invocation would be wrong, not missing, so
//!    these ops carry the operation-level [`DATA_PLANE_MARKER`] extension and
//!    are placed structurally outside the coverable surface (issue #390). The
//!    marker is a parity-gate concern read only here: it does not overload the
//!    runtime `visibility` enum (owned by the gateway contract parser and
//!    pinned to the runtime contract by the drift gate), because `public`
//!    remains the correct HTTP-reachability classification for these routes.
//! 2. [`cli_mapping`] collects the `operationId` every registered CLI verb
//!    claims, keyed so that a *duplicate* mapping (two verbs claiming one
//!    operation) is visible rather than silently de-duplicated the way
//!    [`Registry::coverage_manifest`](crate::command::Registry::coverage_manifest)
//!    is.
//! 3. [`build_report`] diffs the two into covered / missing / extra /
//!    duplicate buckets, honouring a checked-in [`REVIEWED_EXCLUSIONS`] table
//!    so that *known, owned, reasoned* gaps do not fail the gate while *new,
//!    unreviewed* drift does.
//!
//! The parity gate lives in `parity_test.rs`. This module is the reusable,
//! fixture-testable engine underneath it: every function is pure over its
//! inputs (a JSON string, a [`Registry`], an exclusion slice) so the gate can
//! prove it fails on a synthetic gap or duplicate without mutating global
//! state.
//!
//! Scope note (#365 is an epic): this slice ships the coverage manifest +
//! parity report + enforcement gate only. Contract tests, `ferrogate-test`
//! E2E per family, generated docs/completions, and release packaging + SBOM
//! remain open under #365.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::command::Registry;

/// OpenAPI HTTP method keys that denote an operation object under a path item.
const HTTP_METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Contract visibilities whose operations the CLI is expected to cover. An
/// `internal` operation is gateway-internal and intentionally has no operator
/// command, so it is not part of the coverable surface.
const COVERABLE_VISIBILITIES: [&str; 2] = ["public", "admin"];

/// Operation-level OpenAPI extension flag marking a runtime data-plane
/// operation. When `true`, the operation is AI-traffic (OpenAI-compatible
/// inference, MCP/tool execution) rather than a Control-Plane management verb,
/// so it is structurally outside the coverable CLI surface regardless of its
/// (public) HTTP `visibility`. See issue #390.
const DATA_PLANE_MARKER: &str = "x-ferrogate-data-plane";

/// One intentionally-unmapped OpenAPI operation. An entry here is a reviewed,
/// owned decision that the operation carries no CLI verb *yet* (or ever) — it
/// removes the operation from the "missing" gap set so the parity gate stays
/// green, while keeping the reason auditable in source control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewedExclusion {
    /// The OpenAPI `operationId` that intentionally has no CLI verb.
    pub operation_id: &'static str,
    /// Who owns closing (or permanently justifying) the gap.
    pub owner: &'static str,
    /// Why it is unmapped today. Cite the follow-up issue when it is a
    /// not-yet-implemented family rather than a permanent exclusion.
    pub reason: &'static str,
}

/// The reviewed exclusion list: OpenAPI operations that are knowingly not
/// mapped to a CLI verb today. Each carries an owner and a technical reason so
/// the gate reports *reviewed* gaps as green and *new* gaps as red.
///
/// Keep this list minimal and shrinking. When a family lands its verbs, delete
/// the corresponding rows — [`build_report`] flags stale rows (an exclusion
/// whose operation is now covered, or no longer in the contract) so this table
/// cannot rot into a rubber stamp.
pub const REVIEWED_EXCLUSIONS: &[ReviewedExclusion] = &[
    // Agent skill/discovery reads — verbs not yet built. Owner: agent family track (#362 follow-up).
    ReviewedExclusion {
        operation_id: "getAgentDiscovery",
        owner: "agent family (#362)",
        reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
    },
    ReviewedExclusion {
        operation_id: "getAgentSkill",
        owner: "agent family (#362)",
        reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
    },
    ReviewedExclusion {
        operation_id: "listAgentSkills",
        owner: "agent family (#362)",
        reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
    },
    // Self-hosted worker registration verb — not yet built. Owner: worker family track (#362 follow-up).
    ReviewedExclusion {
        operation_id: "registerAdminSelfHostedWorker",
        owner: "worker family (#362)",
        reason:
            "self-hosted worker registration verb not yet implemented; tracked as #362 follow-up",
    },
    // Asset visibility promotion verb — not yet built. Owner: asset family track (#363 follow-up).
    ReviewedExclusion {
        operation_id: "promoteAssetVisibility",
        owner: "asset family (#363)",
        reason: "asset visibility-promotion verb not yet implemented; tracked as #363 follow-up",
    },
    // Scoped control-plane overview read (#339): a single aggregate read whose
    // consumer is the admin-console dashboard (#343), not an operator CLI verb.
    // A `ctl overview` convenience verb, if wanted, is orthogonal follow-up work;
    // excluded here so the server-side endpoint does not falsely read as CLI
    // contract drift. Owner: control-plane console track (#343).
    ReviewedExclusion {
        operation_id: "getAdminOverview",
        owner: "control-plane console (#343)",
        reason: "dashboard-facing control-plane overview aggregate; ctl verb is optional follow-up, tracked with the #343 console UI",
    },
    // Runtime data-plane traffic is NOT excluded here. Two families of runtime
    // AI-traffic operations that were once parked in this allowlist now leave the
    // coverable Control-Plane surface *structurally* via the
    // `x-ferrogate-data-plane` OpenAPI extension (see `DATA_PLANE_MARKER` /
    // `parse_openapi_surface`), not via this ad-hoc list:
    //   - OpenAI-compatible inference + MCP/tool execution: createChatCompletion,
    //     createEmbedding, createImage, createMessage, createResponse,
    //     executeFunction, executeMcpTool, executeTool, listModels, listTools,
    //     mcpJsonRpc.
    //   - Agent-runtime invoke/messaging (A2A): invokeAgent, sendAgentMessage,
    //     streamAgentMessage — these move AI traffic to a configured agent
    //     upstream (request body `AiRequest`, scope `agents.invoke`), the direct
    //     analog of createMessage/createResponse, so classifying them off the
    //     parity surface is the same #390 decision applied uniformly. A management
    //     CLI configures agents (create/update/delete), it does not proxy live
    //     invocation; a future data-plane *client* convenience for them would be
    //     orthogonal to this Control-Plane parity surface, exactly as for
    //     createChatCompletion.
    // Excluding any of these here as well would be a stale, redundant row that the
    // stale-exclusion check would (correctly) reject.
];

/// The coverable and non-coverable operation sets parsed from an OpenAPI
/// document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationSurface {
    /// `operationId`s of `public`/`admin` operations — the set the CLI is
    /// expected to cover.
    pub coverable: BTreeSet<String>,
    /// `operationId`s of `internal` operations — recorded so an accidental CLI
    /// verb for one can be reported as `extra` rather than silently accepted.
    pub internal: BTreeSet<String>,
    /// `operationId`s of runtime data-plane operations (carrying the
    /// [`DATA_PLANE_MARKER`] extension) — AI-traffic endpoints that are not
    /// Control-Plane management verbs and so are not part of the coverable
    /// surface. Recorded so an accidental CLI verb for one surfaces as `extra`.
    pub data_plane: BTreeSet<String>,
}

/// Parse the coverable public surface out of an OpenAPI document (as a JSON
/// string). Fails closed: any operation object missing an `operationId` or a
/// recognisable `x-ferrogate-contract.visibility` is an error, because the
/// parity gate must not silently drop operations from the surface it enforces.
pub fn parse_openapi_surface(json: &str) -> Result<OperationSurface, String> {
    let document: Value =
        serde_json::from_str(json).map_err(|err| format!("failed to parse OpenAPI JSON: {err}"))?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| "OpenAPI document has no `paths` object".to_string())?;

    let mut surface = OperationSurface::default();
    for (route, path_item) in paths {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        for (method, operation) in path_item {
            if !HTTP_METHODS.contains(&method.as_str()) {
                continue;
            }
            let Some(operation) = operation.as_object() else {
                continue;
            };
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    format!("{} {route} is missing operationId", method.to_uppercase())
                })?;
            // Runtime data-plane operations leave the coverable surface on a
            // second axis, independent of their (public) HTTP visibility: they
            // move AI traffic, not Control-Plane configuration (#390).
            if operation
                .get(DATA_PLANE_MARKER)
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                surface.data_plane.insert(operation_id.to_string());
                continue;
            }
            let visibility = operation
                .get("x-ferrogate-contract")
                .and_then(Value::as_object)
                .and_then(|contract| contract.get("visibility"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{} {route} ({operation_id}) is missing x-ferrogate-contract.visibility",
                        method.to_uppercase()
                    )
                })?;
            if COVERABLE_VISIBILITIES.contains(&visibility) {
                surface.coverable.insert(operation_id.to_string());
            } else {
                surface.internal.insert(operation_id.to_string());
            }
        }
    }

    if surface.coverable.is_empty() {
        return Err("OpenAPI document declared no coverable (public/admin) operations".to_string());
    }
    Ok(surface)
}

/// The `operationId`s claimed by the registered CLI verbs, mapped to the
/// human-readable `group verb` sites that claim each one. A key with more than
/// one site is a duplicate mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliMapping {
    /// `operationId` -> the `"group verb"` sites that declare it, sorted.
    pub by_operation: BTreeMap<String, Vec<String>>,
}

impl CliMapping {
    /// The de-duplicated set of covered `operationId`s.
    pub fn operation_ids(&self) -> BTreeSet<String> {
        self.by_operation.keys().cloned().collect()
    }

    /// Operations claimed by more than one verb, mapped to the offending sites.
    pub fn duplicates(&self) -> BTreeMap<String, Vec<String>> {
        self.by_operation
            .iter()
            .filter(|(_, sites)| sites.len() > 1)
            .map(|(id, sites)| (id.clone(), sites.clone()))
            .collect()
    }
}

/// Collect the CLI coverage mapping from every registered command family.
///
/// Reads only the public [`Registry::groups`](crate::command::Registry::groups)
/// surface, so it needs no change to the family-module foundation. Unlike
/// [`Registry::coverage_manifest`](crate::command::Registry::coverage_manifest)
/// (a de-duplicated `BTreeSet`), this preserves *which* verbs claim an
/// operation, which is what makes duplicate detection possible.
pub fn cli_mapping(registry: &Registry) -> CliMapping {
    let mut by_operation: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for group in registry.groups() {
        for verb in &group.verbs {
            if let Some(operation_id) = &verb.operation_id {
                by_operation
                    .entry(operation_id.clone())
                    .or_default()
                    .push(format!("{} {}", group.name, verb.name));
            }
        }
    }
    for sites in by_operation.values_mut() {
        sites.sort();
    }
    CliMapping { by_operation }
}

/// The parity verdict: how the CLI mapping lines up with the coverable OpenAPI
/// surface, after applying the reviewed exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageReport {
    /// Coverable operations that a CLI verb maps.
    pub covered: BTreeSet<String>,
    /// Coverable operations with no CLI verb and no reviewed exclusion — the
    /// gap set that must be empty for the gate to pass.
    pub missing: BTreeSet<String>,
    /// Coverable operations with no CLI verb that are on the reviewed
    /// exclusion list (documented, owned gaps). Not a failure.
    pub excluded_missing: BTreeSet<String>,
    /// `operationId`s a CLI verb claims that are not in the coverable OpenAPI
    /// surface (either absent from the contract, or `internal`) — a verb
    /// pointing at a stale or wrong operation.
    pub extra: BTreeSet<String>,
    /// Operations mapped by more than one verb, keyed to the offending sites.
    pub duplicates: BTreeMap<String, Vec<String>>,
    /// Reviewed-exclusion rows that no longer describe a real coverable gap
    /// (the operation is now covered, or gone from the contract). Stale rows
    /// must be pruned, so the gate treats them as failures too.
    pub stale_exclusions: BTreeSet<String>,
}

impl CoverageReport {
    /// True when there is no unreviewed gap, no duplicate, no extra mapping,
    /// and no stale exclusion — the condition the parity gate asserts.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.extra.is_empty()
            && self.duplicates.is_empty()
            && self.stale_exclusions.is_empty()
    }

    /// A stable, human-readable rendering for test failure output and for the
    /// machine-readable coverage summary.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "OpenAPI-to-CLI parity report\n  covered: {}\n  missing (unreviewed gap): {}\n  excluded (reviewed gap): {}\n  extra (verb -> unknown op): {}\n  duplicate mappings: {}\n  stale exclusions: {}\n",
            self.covered.len(),
            self.missing.len(),
            self.excluded_missing.len(),
            self.extra.len(),
            self.duplicates.len(),
            self.stale_exclusions.len(),
        ));
        push_set(&mut out, "missing (unreviewed gap)", &self.missing);
        push_set(&mut out, "extra (verb -> unknown op)", &self.extra);
        push_set(&mut out, "stale exclusions", &self.stale_exclusions);
        if !self.duplicates.is_empty() {
            out.push_str("  duplicate mappings:\n");
            for (id, sites) in &self.duplicates {
                out.push_str(&format!("    - {id}: {}\n", sites.join(", ")));
            }
        }
        out
    }
}

fn push_set(out: &mut String, label: &str, set: &BTreeSet<String>) {
    if set.is_empty() {
        return;
    }
    out.push_str(&format!("  {label}:\n"));
    for id in set {
        out.push_str(&format!("    - {id}\n"));
    }
}

/// Diff the coverable OpenAPI surface against the CLI mapping, applying the
/// reviewed exclusions, into a [`CoverageReport`].
pub fn build_report(
    surface: &OperationSurface,
    mapping: &CliMapping,
    exclusions: &[ReviewedExclusion],
) -> CoverageReport {
    let covered_ids = mapping.operation_ids();
    let excluded: BTreeSet<String> = exclusions
        .iter()
        .map(|entry| entry.operation_id.to_string())
        .collect();

    let mut report = CoverageReport {
        duplicates: mapping.duplicates(),
        ..CoverageReport::default()
    };

    for id in &surface.coverable {
        if covered_ids.contains(id) {
            report.covered.insert(id.clone());
        } else if excluded.contains(id) {
            report.excluded_missing.insert(id.clone());
        } else {
            report.missing.insert(id.clone());
        }
    }

    for id in &covered_ids {
        if !surface.coverable.contains(id) {
            report.extra.insert(id.clone());
        }
    }

    // A reviewed exclusion is stale if the operation it names is now covered by
    // a verb, or is no longer a coverable operation in the contract.
    for id in &excluded {
        let still_a_gap = surface.coverable.contains(id) && !covered_ids.contains(id);
        if !still_a_gap {
            report.stale_exclusions.insert(id.clone());
        }
    }

    report
}

/// Path (relative to this crate's `Cargo.toml`) of the OpenAPI document the
/// parity gate enforces against. Kept here so the gate and any tooling agree
/// on the single source of public operationIds.
pub const OPENAPI_DOCUMENT_PATH: &str = "../../docs/openapi/admin-api.openapi.json";

#[cfg(test)]
#[path = "parity_test.rs"]
mod parity_test;
