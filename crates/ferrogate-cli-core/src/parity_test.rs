// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! OpenAPI-to-CLI parity gate (issue #365, coverage-manifest slice).
//!
//! These tests are the enforcement half of [`super`]: they assert the *live*
//! CLI mapping against the *live* OpenAPI contract, and they prove the gate is
//! not a rubber stamp by showing it goes red on a synthetic gap, a duplicate
//! mapping, an extra (stale) mapping, and a stale exclusion — using in-memory
//! fixtures so no global state is touched.

use std::collections::BTreeMap;

use super::*;
use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::register_resource_families;

/// Read the live OpenAPI document the gate enforces against.
fn openapi_document() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/admin-api.openapi.json"
    );
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read OpenAPI document at {path}: {err}"))
}

/// The full CLI command surface every registered family contributes.
fn full_registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("resource families register cleanly");
    registry
}

/// The live parity report: live contract, live registry, checked-in exclusions.
fn live_report() -> CoverageReport {
    let surface = parse_openapi_surface(&openapi_document()).expect("OpenAPI surface parses");
    let mapping = cli_mapping(&full_registry());
    build_report(&surface, &mapping, REVIEWED_EXCLUSIONS)
}

// ---------------------------------------------------------------------------
// The gate: the live surface must be clean.
// ---------------------------------------------------------------------------

/// The primary gate. Every coverable OpenAPI operation must be either covered
/// by a CLI verb or on the reviewed-exclusion list; there must be no duplicate
/// mapping, no verb pointing at an unknown operation, and no stale exclusion.
/// A NEW uncovered operation (contract drift) fails here until it is either
/// bound to a verb or added to [`REVIEWED_EXCLUSIONS`] with an owner + reason.
#[test]
fn openapi_operations_are_covered_or_reviewed() {
    let report = live_report();
    assert!(
        report.is_clean(),
        "OpenAPI-to-CLI parity gate failed. Either bind a CLI verb to each \
         operation below or add it to REVIEWED_EXCLUSIONS (parity.rs) with an \
         owner and technical reason.\n\n{}",
        report.render()
    );
}

/// Documents (and pins) the current coverage split so a reviewer sees the shape
/// of the gap the exclusions cover. Not a strict gate on exact counts — it only
/// asserts internal invariants that must always hold.
#[test]
fn live_report_partitions_the_surface_without_overlap() {
    let report = live_report();
    // Covered, excluded-missing, and (unreviewed) missing are disjoint and, for
    // a clean gate, missing is empty — so covered + excluded == coverable total.
    let surface = parse_openapi_surface(&openapi_document()).unwrap();
    assert_eq!(
        report.covered.len() + report.excluded_missing.len() + report.missing.len(),
        surface.coverable.len(),
        "coverable operations must be partitioned into covered/excluded/missing"
    );
    assert!(
        report.covered.is_disjoint(&report.excluded_missing),
        "an operation cannot be both covered and excluded"
    );
    // Every covered id is a real coverable operation (no phantom coverage).
    for id in &report.covered {
        assert!(surface.coverable.contains(id));
    }
}

/// `internal`-visibility operations are not part of the coverable surface, so
/// the CLI is neither expected nor allowed to bind a verb to them.
#[test]
fn internal_operations_are_not_coverable() {
    let surface = parse_openapi_surface(&openapi_document()).unwrap();
    // `getMetrics` is an internal scrape endpoint in the live contract.
    assert!(
        surface.internal.contains("getMetrics"),
        "expected getMetrics to be classified internal"
    );
    assert!(
        !surface.coverable.contains("getMetrics"),
        "internal operations must not be in the coverable surface"
    );
}

// ---------------------------------------------------------------------------
// Exclusion-table hygiene.
// ---------------------------------------------------------------------------

/// Every reviewed exclusion must carry a non-empty owner and reason, and no
/// operation may be excluded twice — so the table stays an auditable ledger.
#[test]
fn reviewed_exclusions_are_well_formed() {
    let mut seen = BTreeMap::new();
    for entry in REVIEWED_EXCLUSIONS {
        assert!(
            !entry.operation_id.is_empty(),
            "exclusion has empty operation_id"
        );
        assert!(
            !entry.owner.trim().is_empty(),
            "exclusion {} has no owner",
            entry.operation_id
        );
        assert!(
            !entry.reason.trim().is_empty(),
            "exclusion {} has no reason",
            entry.operation_id
        );
        assert!(
            seen.insert(entry.operation_id, ()).is_none(),
            "operation {} is excluded more than once",
            entry.operation_id
        );
    }
}

/// Every reviewed exclusion must correspond to a real, currently-uncovered
/// coverable operation. This is what keeps the list from rotting: once a family
/// lands its verbs (or the operation leaves the contract) the row becomes stale
/// and must be deleted.
#[test]
fn reviewed_exclusions_are_not_stale() {
    let report = live_report();
    assert!(
        report.stale_exclusions.is_empty(),
        "these reviewed exclusions no longer describe a real gap and must be \
         pruned from REVIEWED_EXCLUSIONS:\n{:#?}",
        report.stale_exclusions
    );
}

// ---------------------------------------------------------------------------
// Proof the gate actually catches drift (in-memory fixtures).
// ---------------------------------------------------------------------------

/// A minimal OpenAPI document exposing a single coverable operation.
fn fixture_surface(operation_id: &str, visibility: &str) -> String {
    format!(
        r#"{{"paths":{{"/fixture":{{"get":{{"operationId":"{operation_id}",
        "x-ferrogate-contract":{{"visibility":"{visibility}"}}}}}}}}}}"#
    )
}

/// A single-verb command family for constructing synthetic mappings.
struct FixtureGroup {
    group: &'static str,
    verb: &'static str,
    operation_id: &'static str,
}

impl CommandGroup for FixtureGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            self.group,
            "fixture",
            vec![VerbDescriptor::api(
                self.verb,
                "fixture verb",
                self.operation_id,
            )],
        )
    }
}

/// An un-excluded, uncovered coverable operation is reported as a missing gap
/// and fails the gate.
#[test]
fn gate_fails_on_unreviewed_gap() {
    let surface = parse_openapi_surface(&fixture_surface("syntheticUncoveredOp", "admin")).unwrap();
    let empty = cli_mapping(&Registry::new());
    let report = build_report(&surface, &empty, &[]);
    assert!(report.missing.contains("syntheticUncoveredOp"));
    assert!(!report.is_clean(), "an unreviewed gap must fail the gate");
}

/// The same synthetic gap passes once it is placed on the reviewed-exclusion
/// list — proving exclusions are the sanctioned escape hatch.
#[test]
fn gate_passes_when_gap_is_reviewed() {
    let surface = parse_openapi_surface(&fixture_surface("syntheticUncoveredOp", "admin")).unwrap();
    let empty = cli_mapping(&Registry::new());
    let exclusions = [ReviewedExclusion {
        operation_id: "syntheticUncoveredOp",
        owner: "test",
        reason: "fixture",
    }];
    let report = build_report(&surface, &empty, &exclusions);
    assert!(report.missing.is_empty());
    assert!(report.excluded_missing.contains("syntheticUncoveredOp"));
    assert!(report.is_clean(), "a reviewed gap must pass the gate");
}

/// Two verbs claiming one operationId is a duplicate mapping and fails the gate.
#[test]
fn gate_fails_on_duplicate_mapping() {
    let mut registry = Registry::new();
    registry
        .register(&FixtureGroup {
            group: "alpha",
            verb: "list",
            operation_id: "sharedOperation",
        })
        .unwrap();
    registry
        .register(&FixtureGroup {
            group: "beta",
            verb: "list",
            operation_id: "sharedOperation",
        })
        .unwrap();
    let mapping = cli_mapping(&registry);
    let surface = parse_openapi_surface(&fixture_surface("sharedOperation", "admin")).unwrap();
    let report = build_report(&surface, &mapping, &[]);

    let duplicates = report
        .duplicates
        .get("sharedOperation")
        .expect("duplicate detected");
    assert_eq!(
        duplicates,
        &vec!["alpha list".to_string(), "beta list".to_string()]
    );
    assert!(!report.is_clean(), "a duplicate mapping must fail the gate");
}

/// A verb pointing at an operationId absent from the coverable surface is an
/// `extra` (stale/typo'd) mapping and fails the gate.
#[test]
fn gate_fails_on_extra_mapping() {
    let mut registry = Registry::new();
    registry
        .register(&FixtureGroup {
            group: "alpha",
            verb: "list",
            operation_id: "operationNotInContract",
        })
        .unwrap();
    let mapping = cli_mapping(&registry);
    let surface = parse_openapi_surface(&fixture_surface("someOtherOperation", "admin")).unwrap();
    let report = build_report(&surface, &mapping, &[]);
    assert!(report.extra.contains("operationNotInContract"));
    assert!(!report.is_clean(), "an extra mapping must fail the gate");
}

/// An exclusion naming an operation that is actually covered is stale and fails.
#[test]
fn gate_fails_on_stale_exclusion() {
    let mut registry = Registry::new();
    registry
        .register(&FixtureGroup {
            group: "alpha",
            verb: "list",
            operation_id: "coveredOperation",
        })
        .unwrap();
    let mapping = cli_mapping(&registry);
    let surface = parse_openapi_surface(&fixture_surface("coveredOperation", "admin")).unwrap();
    let exclusions = [ReviewedExclusion {
        operation_id: "coveredOperation",
        owner: "test",
        reason: "no longer a gap",
    }];
    let report = build_report(&surface, &mapping, &exclusions);
    assert!(report.stale_exclusions.contains("coveredOperation"));
    assert!(!report.is_clean(), "a stale exclusion must fail the gate");
}

// ---------------------------------------------------------------------------
// Parser fail-closed behaviour.
// ---------------------------------------------------------------------------

/// An operation missing its `operationId` is a parse error, not a silent drop.
#[test]
fn parse_rejects_operation_without_operation_id() {
    let json = r#"{"paths":{"/x":{"get":{"x-ferrogate-contract":{"visibility":"admin"}}}}}"#;
    let error = parse_openapi_surface(json).unwrap_err();
    assert!(error.contains("missing operationId"), "got: {error}");
}

/// An operation missing its visibility classification is a parse error.
#[test]
fn parse_rejects_operation_without_visibility() {
    let json = r#"{"paths":{"/x":{"get":{"operationId":"noVis"}}}}"#;
    let error = parse_openapi_surface(json).unwrap_err();
    assert!(error.contains("visibility"), "got: {error}");
}

/// A document with no coverable operations is rejected (guards against a parse
/// that silently produces an empty surface the gate would trivially pass).
#[test]
fn parse_rejects_surface_with_no_coverable_operations() {
    let json = r#"{"paths":{"/x":{"get":{"operationId":"onlyInternal",
    "x-ferrogate-contract":{"visibility":"internal"}}}}}"#;
    let error = parse_openapi_surface(json).unwrap_err();
    assert!(error.contains("no coverable"), "got: {error}");
}
