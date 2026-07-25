// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for coding-agent contract phase 4
//   (issue #472): the deliverable is a run-attributed diff, an empty change is not a work product.

use super::*;
use crate::coding_agent::materialize::RepoCoordinates;
use crate::coding_agent::run::CodingRunIdentity;

const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "3333333333333333333333333333333333333333";

const PATCH: &str = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "widget").expect("coordinates")
}

fn base() -> PinnedRef {
    PinnedRef::new(BASE).expect("pin")
}

fn run() -> CodingRunIdentity {
    CodingRunIdentity::new("tenant-a", "session-1", "run-1")
}

fn product(run: CodingRunIdentity) -> WorkProduct {
    WorkProduct::assemble(
        run,
        repo(),
        base(),
        Some(ProducedBranch::new("ferrogate/run-1-fix", HEAD, base()).expect("branch")),
        UnifiedDiff::inline(PATCH).expect("diff"),
        DiffStats {
            files_changed: 1,
            insertions: 1,
            deletions: 1,
        },
        Some("swapped old for new".to_string()),
        1_200,
    )
    .expect("work product")
}

#[test]
fn an_empty_change_is_not_a_work_product() {
    assert_eq!(
        UnifiedDiff::inline("   \n").expect_err("empty patch"),
        CodingAgentError::EmptyWorkProduct
    );
    assert_eq!(
        UnifiedDiff::artifact("artifact://run-1/diff", "sha256:abc", 0).expect_err("empty"),
        CodingAgentError::EmptyWorkProduct
    );
    // A branch whose head is still the base changed nothing.
    assert_eq!(
        ProducedBranch::new("ferrogate/run-1", BASE, base()).expect_err("no commits"),
        CodingAgentError::EmptyWorkProduct
    );
}

#[test]
fn the_product_id_is_derived_and_checkable() {
    let extracted = product(run());
    assert_eq!(
        WORK_PRODUCT_ID_CONTRACT,
        "sha256(tenant|run|repo|base_commit|diff_digest)"
    );
    assert!(crate::is_canonical_action_fingerprint(
        extracted.product_id()
    ));
    assert!(extracted.id_is_consistent());
    assert!(extracted.attributed_to("run-1"));
    assert!(!extracted.attributed_to("run-2"));

    // Deterministic: re-extracting the same tree for the same run is idempotent.
    assert_eq!(extracted.product_id(), product(run()).product_id());

    // A different run over the same tree is a different product.
    let other = product(CodingRunIdentity::new("tenant-a", "session-1", "run-2"));
    assert_ne!(extracted.product_id(), other.product_id());
}

#[test]
fn relabelling_the_run_breaks_attribution_instead_of_faking_it() {
    let mut product = product(run());
    product.run.run_id = "run-2".to_string();
    assert!(!product.id_is_consistent());
    assert!(!product.attributed_to("run-2"));
    assert!(!product.attributed_to("run-1"));
}

/// Defect 1 from the #472 review: `repo` was a public field left *out* of the
/// derivation, so a diff extracted from repo A could be relabelled to repo B
/// and `id_is_consistent()` still returned `true`. "Which repository this diff
/// came from" is the one property this type exists to provide, so it must break
/// the id exactly as relabelling the run does.
#[test]
fn relabelling_the_repo_breaks_provenance_instead_of_faking_it() {
    let mut product = product(run());
    assert!(product.extracted_from(&repo()));

    let other = RepoCoordinates::new("github", "github.com", "acme", "other").expect("coordinates");
    product.repo = other.clone();
    assert!(!product.id_is_consistent());
    assert!(!product.extracted_from(&other));
    assert!(!product.extracted_from(&repo()));
    // Attribution is derived from the same id, so it fails too.
    assert!(!product.attributed_to("run-1"));

    // ...and two identical diffs from two repos are two products.
    let from_other = WorkProduct::assemble(
        run(),
        other,
        base(),
        None,
        UnifiedDiff::inline(PATCH).expect("diff"),
        DiffStats::default(),
        None,
        1_200,
    )
    .expect("work product");
    let from_repo = WorkProduct::assemble(
        run(),
        repo(),
        base(),
        None,
        UnifiedDiff::inline(PATCH).expect("diff"),
        DiffStats::default(),
        None,
        1_200,
    )
    .expect("work product");
    assert_ne!(from_other.product_id(), from_repo.product_id());
}

#[test]
fn the_diff_is_content_addressed_in_both_carriers() {
    let inline = UnifiedDiff::inline(PATCH).expect("diff");
    assert!(inline.verify_inline());
    assert_eq!(inline.byte_len(), PATCH.len() as u64);
    assert_eq!(inline.inline_patch(), Some(PATCH));
    assert!(crate::is_canonical_action_fingerprint(inline.digest()));

    let artifact = UnifiedDiff::artifact("artifact://run-1/diff", inline.digest(), 4_096)
        .expect("artifact diff");
    assert_eq!(artifact.digest(), inline.digest());
    assert_eq!(artifact.inline_patch(), None);
    assert!(matches!(artifact.body(), DiffBody::Artifact { .. }));

    // An artifact diff without a content digest cannot be attributed.
    assert!(matches!(
        UnifiedDiff::artifact("artifact://run-1/diff", "opaque-id", 4_096),
        Err(CodingAgentError::InvalidRequest { .. })
    ));
}

#[test]
fn a_branch_must_be_based_on_the_diff_base() {
    let other_base = PinnedRef::new("2222222222222222222222222222222222222222").expect("pin");
    let mismatched = WorkProduct::assemble(
        run(),
        repo(),
        base(),
        Some(ProducedBranch::new("ferrogate/run-1", HEAD, other_base).expect("branch")),
        UnifiedDiff::inline(PATCH).expect("diff"),
        DiffStats::default(),
        None,
        1_200,
    );
    assert!(matches!(
        mismatched,
        Err(CodingAgentError::InvalidRequest { .. })
    ));
}

#[test]
fn the_summary_is_advisory_and_the_diff_is_the_deliverable() {
    let product = product(run());
    // Prose does not participate in identity: two runs with different
    // narration over the same change produce the same product id.
    let mut narrated = product.clone();
    narrated.summary = Some("a completely different story".to_string());
    assert_eq!(product.product_id(), narrated.product_id());
    assert!(narrated.id_is_consistent());
}

#[test]
fn the_request_defaults_to_a_bounded_inline_diff() {
    let workspace = MaterializedWorkspace {
        run: run(),
        repo: repo(),
        workspace_path: "/workspace".to_string(),
        materialized_ref: base(),
        credential_grant_id: "grant-1".to_string(),
        materialized_at_unix: 1_100,
    };
    let request = WorkProductRequest::new(run(), workspace, base());
    assert_eq!(request.max_inline_diff_bytes, DEFAULT_MAX_INLINE_DIFF_BYTES);
}
