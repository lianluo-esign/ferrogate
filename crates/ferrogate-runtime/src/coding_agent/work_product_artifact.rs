// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, the control-plane read path for a coding
//   run's work product (issue #472): the artifact envelope written onto the run timeline and the
//   re-verified projection #474's GET /v1/agent-jobs/{run_id}/result serves from it.

//! **The control-plane read path for phase 4's deliverable.**
//!
//! The issue's acceptance is that result extraction produces a diff
//! attributable to a specific `run_id` *and retrievable through the control
//! plane*. This module is the retrieval half, and it is deliberately **not** a
//! new route, a new table, or a new repository trait.
//!
//! ## Why it composes with #474 instead of paralleling it
//!
//! #474 already landed the caller-facing async job surface, and its result
//! verb — `GET /v1/agent-jobs/{run_id}/result` — is already documented as
//! "where the diff/PR reference lands, #472". It reuses the durable evidence
//! the platform already keeps: the run timeline, whose `artifact`-kind events
//! carry a free-form `event_json`, tenant-scoped at the storage query layer.
//!
//! So a work product is published by writing **one artifact event** whose
//! payload is a [`WorkProductArtifact`], and it is read back by projecting
//! those events on the existing result route. A second `/admin/v1/…/
//! work-products/{id}` route would have meant a second durable store, a second
//! tenant-isolation implementation, and a second thing to keep consistent with
//! the run's terminal state — for a resource that has no life outside its run.
//!
//! ## The one thing the reader must not do: trust the payload
//!
//! A timeline artifact event is *worker-reported* evidence
//! (`trust_level: reported_by_self_hosted_worker`). The reader therefore
//! re-derives attribution instead of believing the `run` field:
//! [`WorkProductView::from_artifact`] reports
//! [`WorkProductView::attribution_verified`] only when
//! [`WorkProduct::attributed_to`] holds against the `run_id` **in the request
//! path**, and [`WorkProductView::repo_verified`] only when the repo is the one
//! folded into the derived id. A relabelled record is still returned — hiding
//! it would hide the tampering — but it is returned marked.
//!
//! The patch bytes themselves are never inlined into the projection. A review
//! surface needs the digest, the stats and the branch; the bytes are fetched
//! from the artifact channel by the reference the envelope carries, so one
//! result read cannot be turned into a megabyte-per-poll amplifier.

use serde::{Deserialize, Serialize};

use crate::coding_agent::extract::{DiffBody, DiffStats, WorkProduct};
use crate::coding_agent::write_back::WriteBackReceipt;

/// Timeline event `kind` a work-product envelope is written under. The same
/// `artifact` kind #415's container artifacts already use — the envelope is
/// distinguished by [`WORK_PRODUCT_ARTIFACT_OBJECT`] inside the payload, not by
/// a new event kind the storage layer would have to learn.
pub const WORK_PRODUCT_ARTIFACT_EVENT_KIND: &str = "artifact";

/// Discriminator inside the artifact payload. A reader that does not recognise
/// it must skip the event, not fail the read: a run's timeline legitimately
/// carries artifacts that are not work products.
pub const WORK_PRODUCT_ARTIFACT_OBJECT: &str = "coding_agent.work_product";

/// The payload written into an `artifact` timeline event's `event_json`.
///
/// `Deserialize` on purpose, unlike
/// [`crate::coding_agent::AuthorizedWriteBack`]: this is *evidence being read
/// back*, not a capability. Nothing is authorized by parsing one, and every
/// claim it makes is re-derived by [`WorkProductView::from_artifact`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkProductArtifact {
    /// Always [`WORK_PRODUCT_ARTIFACT_OBJECT`].
    pub object: String,
    pub work_product: WorkProduct,
    /// The publication receipt, when the run had a grant and pushed. `None` is
    /// the default: a diff exists, nothing left the platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_back: Option<WriteBackReceipt>,
}

impl WorkProductArtifact {
    pub fn new(work_product: WorkProduct, write_back: Option<WriteBackReceipt>) -> Self {
        Self {
            object: WORK_PRODUCT_ARTIFACT_OBJECT.to_string(),
            work_product,
            write_back,
        }
    }

    /// Render the `event_json` body of the timeline artifact event.
    pub fn to_event_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse one timeline artifact payload.
    ///
    /// `None` — never an error — for any payload that is not a work-product
    /// envelope, so an unrelated artifact on the same run cannot fail the
    /// whole result read.
    pub fn parse(event_json: &str) -> Option<Self> {
        let parsed: Self = serde_json::from_str(event_json).ok()?;
        (parsed.object == WORK_PRODUCT_ARTIFACT_OBJECT).then_some(parsed)
    }
}

/// The re-verified, bounded projection a control-plane read returns.
///
/// Deliberately not `WorkProduct` itself: a read surface should hand back the
/// facts a reviewer needs plus the verdict on whether they check out, and
/// should not hand back a patch body inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkProductView {
    pub object: &'static str,
    pub product_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub repo_id: String,
    pub base_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    pub diff_digest: String,
    pub diff_byte_len: u64,
    /// `inline` or `artifact` — where the patch bytes are.
    pub diff_carrier: &'static str,
    /// Present only for the artifact carrier: the reference to fetch the bytes
    /// by. The bytes are never inlined into this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_artifact_ref: Option<String>,
    pub stats: DiffStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub extracted_at_unix: u64,
    /// `true` only when [`WorkProduct::attributed_to`] holds for the `run_id`
    /// the caller asked about — re-derived here, not copied from the record.
    pub attribution_verified: bool,
    /// `true` only when the recorded repo is the one folded into the derived
    /// product id. `false` means the record was relabelled after extraction.
    pub repo_verified: bool,
    /// Where the change was published, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<PublishedChange>,
}

/// What left the platform for this work product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedChange {
    pub operation: String,
    pub branch: String,
    pub head_commit: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reference: Option<String>,
    pub grant_id: String,
    /// Target-level fingerprint from the authorizing `ActionIdentity`, so the
    /// read joins to the `vcs.write_back` audit row without a second lookup.
    pub action_fingerprint: String,
    pub completed_at_unix: u64,
    /// `true` only when the receipt describes publishing *this* product from
    /// *this* run in *this* tenant. The same cross-check the terminal run
    /// receipt applies, repeated at read time because the timeline event and
    /// the run row are written independently.
    pub matches_work_product: bool,
}

impl WorkProductView {
    /// Project one artifact envelope for the run in the request path.
    ///
    /// `run_id` is the caller's, not the payload's: that is the whole point of
    /// re-deriving attribution here.
    pub fn from_artifact(artifact: &WorkProductArtifact, run_id: &str) -> Self {
        let product = &artifact.work_product;
        let (diff_carrier, diff_artifact_ref) = match product.diff.body() {
            DiffBody::Inline { .. } => ("inline", None),
            DiffBody::Artifact { artifact_ref } => ("artifact", Some(artifact_ref.clone())),
        };
        let published = artifact.write_back.as_ref().map(|receipt| PublishedChange {
            operation: receipt.operation.as_str().to_string(),
            branch: receipt.branch.clone(),
            head_commit: receipt.head_commit.clone(),
            outcome: receipt.outcome.as_str().to_string(),
            review_reference: receipt.review_reference.clone(),
            grant_id: receipt.grant_id.clone(),
            action_fingerprint: receipt.action_fingerprint.clone(),
            completed_at_unix: receipt.completed_at_unix,
            matches_work_product: receipt_publishes(receipt, product),
        });
        Self {
            object: "coding_agent_work_product",
            product_id: product.product_id().to_string(),
            run_id: product.run.run_id.clone(),
            tenant_id: product.run.tenant_id.clone(),
            repo_id: product.repo.canonical_id(),
            base_commit: product.base.commit_id().to_string(),
            branch: product.branch.as_ref().map(|branch| branch.name.clone()),
            head_commit: product
                .branch
                .as_ref()
                .map(|branch| branch.head_commit.clone()),
            diff_digest: product.diff.digest().to_string(),
            diff_byte_len: product.diff.byte_len(),
            diff_carrier,
            diff_artifact_ref,
            stats: product.stats,
            summary: product.summary.clone(),
            extracted_at_unix: product.extracted_at_unix,
            attribution_verified: product.attributed_to(run_id),
            repo_verified: product.extracted_from(&product.repo),
            published,
        }
    }

    /// Project every work product on a run's timeline, newest last.
    ///
    /// `events` is `(kind, event_json)` straight off the run timeline. Events
    /// of another kind, and artifacts that are not work-product envelopes, are
    /// skipped rather than erroring.
    pub fn from_timeline_events<'a, I>(events: I, run_id: &str) -> Vec<Self>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        events
            .into_iter()
            .filter(|(kind, _)| *kind == WORK_PRODUCT_ARTIFACT_EVENT_KIND)
            .filter_map(|(_, event_json)| WorkProductArtifact::parse(event_json))
            .map(|artifact| Self::from_artifact(&artifact, run_id))
            .collect()
    }
}

/// The same cross-check `CodingRunReceipt::assemble` performs, applied at read
/// time: a receipt quoting the right product id but an unrelated commit is not
/// a publication of that product.
fn receipt_publishes(receipt: &WriteBackReceipt, product: &WorkProduct) -> bool {
    if receipt.work_product_id != product.product_id()
        || receipt.tenant_id != product.run.tenant_id
        || receipt.run_id != product.run.run_id
        || receipt.repo_id != product.repo.canonical_id()
    {
        return false;
    }
    match &product.branch {
        Some(branch) => receipt.head_commit == branch.head_commit && receipt.branch == branch.name,
        None => false,
    }
}

#[cfg(test)]
#[path = "work_product_artifact_test.rs"]
mod tests;
