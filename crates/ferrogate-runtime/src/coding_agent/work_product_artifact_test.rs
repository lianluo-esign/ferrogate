// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for the coding-agent work-product
//   control-plane read path (issue #472): the timeline artifact envelope round-trips, and the
//   projection re-derives attribution instead of trusting worker-reported evidence.

use std::collections::BTreeSet;

use super::*;
use crate::coding_agent::extract::{ProducedBranch, UnifiedDiff};
use crate::coding_agent::materialize::{PinnedRef, RepoCoordinates};
use crate::coding_agent::run::CodingRunIdentity;
use crate::coding_agent::write_back::{
    authorize_write_back, WriteBackGrant, WriteBackOperation, WriteBackOutcome, WriteBackRequest,
};
use crate::{ActingPrincipal, ActionContext};

const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "3333333333333333333333333333333333333333";
const PATCH: &str = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "widget").expect("coordinates")
}

fn run() -> CodingRunIdentity {
    CodingRunIdentity::new("tenant-a", "session-1", "run-1")
}

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        subject: "api-key-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        worker_id: None,
        delegated_user: None,
    }
}

fn product() -> WorkProduct {
    WorkProduct::assemble(
        run(),
        repo(),
        PinnedRef::new(BASE).expect("pin"),
        Some(
            ProducedBranch::new(
                "ferrogate/run-1-fix",
                HEAD,
                PinnedRef::new(BASE).expect("pin"),
            )
            .expect("branch"),
        ),
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

fn write_back(product: &WorkProduct, head_commit: &str) -> WriteBackReceipt {
    let mut operations = BTreeSet::new();
    operations.insert(WriteBackOperation::PushBranch);
    let grant = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations,
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    )
    .expect("grant");
    let request = WriteBackRequest {
        run: run(),
        repo: repo(),
        operation: WriteBackOperation::PushBranch,
        branch: "ferrogate/run-1-fix".to_string(),
        work_product_id: product.product_id().to_string(),
        head_commit: head_commit.to_string(),
        title: None,
        body: None,
    };
    let authorized = authorize_write_back(
        Some(&grant),
        &request,
        &principal(),
        &ActionContext::for_request("req-1"),
        1_210,
    )
    .expect("evaluable")
    .into_authorized()
    .expect("granted");
    WriteBackReceipt::from_authorized(
        &authorized,
        Some("https://github.com/acme/widget/pull/7".to_string()),
        1_220,
        WriteBackOutcome::Completed,
    )
}

#[test]
fn the_envelope_round_trips_through_one_timeline_artifact_event() {
    let product = product();
    let artifact = WorkProductArtifact::new(product.clone(), Some(write_back(&product, HEAD)));
    let event_json = artifact.to_event_json().expect("serializes");

    let parsed = WorkProductArtifact::parse(&event_json).expect("parses back");
    assert_eq!(parsed.object, WORK_PRODUCT_ARTIFACT_OBJECT);
    assert_eq!(parsed.work_product.product_id(), product.product_id());
    assert!(parsed.work_product.attributed_to("run-1"));

    // Unrelated artifacts on the same run are skipped, not errors: a run's
    // timeline legitimately carries #415 container artifacts too.
    assert!(WorkProductArtifact::parse(r#"{"object":"container.artifact"}"#).is_none());
    assert!(WorkProductArtifact::parse("not json").is_none());
    assert!(WorkProductArtifact::parse("{}").is_none());
}

#[test]
fn the_read_path_projects_a_run_s_work_products_off_the_existing_timeline() {
    let product = product();
    let artifact = WorkProductArtifact::new(product.clone(), Some(write_back(&product, HEAD)));
    let event_json = artifact.to_event_json().expect("serializes");

    let views = WorkProductView::from_timeline_events(
        [
            // Not an artifact event.
            ("lifecycle", r#"{"state":"running"}"#),
            // An artifact that is not a work product.
            (
                "artifact",
                r#"{"object":"container.artifact","path":"/out/log"}"#,
            ),
            ("artifact", event_json.as_str()),
        ],
        "run-1",
    );
    assert_eq!(views.len(), 1);
    let view = &views[0];
    assert_eq!(view.object, "coding_agent_work_product");
    assert_eq!(view.product_id, product.product_id());
    assert_eq!(view.run_id, "run-1");
    assert_eq!(view.tenant_id, "tenant-a");
    assert_eq!(view.repo_id, "github:github.com/acme/widget");
    assert_eq!(view.base_commit, BASE);
    assert_eq!(view.branch.as_deref(), Some("ferrogate/run-1-fix"));
    assert_eq!(view.head_commit.as_deref(), Some(HEAD));
    assert_eq!(view.diff_carrier, "inline");
    assert_eq!(view.diff_byte_len, PATCH.len() as u64);
    assert!(view.attribution_verified);
    assert!(view.repo_verified);

    let published = view.published.as_ref().expect("it was pushed");
    assert_eq!(published.operation, "push_branch");
    assert_eq!(published.head_commit, HEAD);
    assert!(published.matches_work_product);
    assert!(crate::is_canonical_action_fingerprint(
        &published.action_fingerprint
    ));

    // The patch bytes are not in the projection: one result read is not a
    // per-poll megabyte amplifier.
    let rendered = serde_json::to_string(view).expect("json");
    assert!(!rendered.contains("+new"), "rendered: {rendered}");
    assert!(rendered.contains(view.diff_digest.as_str()));
}

/// The timeline event is worker-reported evidence, so the reader re-derives
/// attribution rather than believing the `run`/`repo` fields it was handed.
#[test]
fn a_relabelled_record_is_returned_marked_rather_than_believed_or_hidden() {
    let mut relabelled_run = product();
    relabelled_run.run.run_id = "run-9".to_string();
    let artifact = WorkProductArtifact::new(relabelled_run, None);

    // Asked about run-1, handed a record claiming run-9.
    let view = WorkProductView::from_artifact(&artifact, "run-1");
    assert!(!view.attribution_verified);
    // Hiding it would hide the tampering.
    assert_eq!(view.run_id, "run-9");

    // Even asked about the run it claims, the derived id no longer matches.
    let view = WorkProductView::from_artifact(&artifact, "run-9");
    assert!(!view.attribution_verified);

    // A relabelled repo is caught the same way (defect 1 of the #472 review).
    let mut relabelled_repo = product();
    relabelled_repo.repo =
        RepoCoordinates::new("github", "github.com", "acme", "other").expect("repo");
    let view =
        WorkProductView::from_artifact(&WorkProductArtifact::new(relabelled_repo, None), "run-1");
    assert!(!view.repo_verified);
    assert!(!view.attribution_verified);
}

/// The same cross-check the terminal run receipt applies, repeated at read
/// time: the timeline event and the run row are written independently, so a
/// receipt quoting the right product id and an unrelated commit must not read
/// back as "published".
#[test]
fn a_write_back_receipt_that_does_not_match_the_product_reads_back_unverified() {
    let product = product();
    let stray = write_back(&product, "4444444444444444444444444444444444444444");
    let artifact = WorkProductArtifact::new(product, Some(stray));
    let view = WorkProductView::from_artifact(&artifact, "run-1");
    let published = view.published.expect("a receipt is present");
    assert!(!published.matches_work_product);
    assert_eq!(
        published.head_commit,
        "4444444444444444444444444444444444444444"
    );
}

#[test]
fn an_artifact_carried_diff_is_referenced_not_inlined() {
    let product = WorkProduct::assemble(
        run(),
        repo(),
        PinnedRef::new(BASE).expect("pin"),
        None,
        UnifiedDiff::artifact(
            "artifact://run-1/diff",
            crate::opaque_reference_fingerprint(PATCH),
            4_096,
        )
        .expect("artifact diff"),
        DiffStats::default(),
        None,
        1_200,
    )
    .expect("work product");
    let view = WorkProductView::from_artifact(&WorkProductArtifact::new(product, None), "run-1");
    assert_eq!(view.diff_carrier, "artifact");
    assert_eq!(
        view.diff_artifact_ref.as_deref(),
        Some("artifact://run-1/diff")
    );
    assert_eq!(view.diff_byte_len, 4_096);
    assert!(view.attribution_verified);
    assert!(view.branch.is_none());
    assert!(view.published.is_none());
}
