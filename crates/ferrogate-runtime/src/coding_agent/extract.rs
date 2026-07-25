// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472),
//   phase 4: result extraction — a run-attributed diff/branch work product, not a chat completion.

//! **Phase 4 — result extraction.**
//!
//! The deliverable of a coding run is a **diff**, optionally carried by a
//! branch, attributable to exactly one `run_id` and applying to exactly one
//! base commit. It is not a chat completion, and the contract has no field for
//! one: an assistant message is at most [`WorkProduct::summary`], which is
//! explicitly advisory and carries no authority over what the diff contains.
//!
//! [`WorkProduct::product_id`] is derived, not assigned:
//! `sha256(tenant|run_id|base_commit|diff_digest)`. Two consequences worth
//! having on purpose:
//!
//! * The same run re-extracting the same tree yields the same id (idempotent
//!   retry).
//! * A work product cannot be re-attributed to a different run without the id
//!   changing, so [`WorkProduct::attributed_to`] is a check, not a convention.
//!
//! An empty diff is refused by [`WorkProduct::assemble`]. "The agent changed
//! nothing" is a real and reportable outcome — it must surface as *no work
//! product*, never as an empty patch that reads like a reviewable change.

use serde::{Deserialize, Serialize};

use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::materialize::{MaterializedWorkspace, PinnedRef, RepoCoordinates};
use crate::coding_agent::run::CodingRunIdentity;
use crate::opaque_reference_fingerprint;

/// Contract label for how [`WorkProduct::product_id`] is derived, so a
/// consumer can verify attribution instead of trusting it.
pub const WORK_PRODUCT_ID_CONTRACT: &str = "sha256(tenant|run|base_commit|diff_digest)";

/// Default inline-diff ceiling. Above it the patch belongs in the artifact
/// channel (the #415 container artifact collection), referenced by digest.
pub const DEFAULT_MAX_INLINE_DIFF_BYTES: u64 = 1_048_576;

/// Line counts for the change. Cheap triage before anyone opens the patch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffStats {
    pub files_changed: u32,
    pub insertions: u64,
    pub deletions: u64,
}

/// Where the patch bytes live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "body", rename_all = "snake_case")]
pub enum DiffBody {
    /// The unified diff itself, small enough to carry.
    Inline { patch: String },
    /// A reference into the artifact channel. The digest on
    /// [`UnifiedDiff`] still pins the content, so attribution survives the
    /// indirection.
    Artifact { artifact_ref: String },
}

/// A unified diff, content-addressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedDiff {
    digest: String,
    byte_len: u64,
    body: DiffBody,
}

impl UnifiedDiff {
    /// Carry the patch inline. Refuses an empty or whitespace-only patch.
    pub fn inline(patch: impl Into<String>) -> Result<Self, CodingAgentError> {
        let patch = patch.into();
        if patch.trim().is_empty() {
            return Err(CodingAgentError::EmptyWorkProduct);
        }
        Ok(Self {
            digest: opaque_reference_fingerprint(&patch),
            byte_len: patch.len() as u64,
            body: DiffBody::Inline { patch },
        })
    }

    /// Reference a patch held in the artifact channel. The caller supplies the
    /// digest computed over the same bytes it stored.
    pub fn artifact(
        artifact_ref: impl Into<String>,
        digest: impl Into<String>,
        byte_len: u64,
    ) -> Result<Self, CodingAgentError> {
        let digest = digest.into();
        if byte_len == 0 {
            return Err(CodingAgentError::EmptyWorkProduct);
        }
        if !digest.starts_with("sha256:") {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Extract,
                "diff.digest",
                "artifact diffs must carry a sha256: digest over the stored bytes",
            ));
        }
        Ok(Self {
            digest,
            byte_len,
            body: DiffBody::Artifact {
                artifact_ref: artifact_ref.into(),
            },
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn body(&self) -> &DiffBody {
        &self.body
    }

    /// The patch text when it is carried inline.
    pub fn inline_patch(&self) -> Option<&str> {
        match &self.body {
            DiffBody::Inline { patch } => Some(patch.as_str()),
            DiffBody::Artifact { .. } => None,
        }
    }

    /// Re-verify inline content against the recorded digest.
    pub fn verify_inline(&self) -> bool {
        match &self.body {
            DiffBody::Inline { patch } => opaque_reference_fingerprint(patch) == self.digest,
            DiffBody::Artifact { .. } => true,
        }
    }
}

/// A branch the run produced inside the workspace. Producing it is local;
/// publishing it is phase 5 and needs a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducedBranch {
    pub name: String,
    pub head_commit: String,
    pub base: PinnedRef,
}

impl ProducedBranch {
    pub fn new(
        name: impl Into<String>,
        head_commit: impl Into<String>,
        base: PinnedRef,
    ) -> Result<Self, CodingAgentError> {
        let name = name.into();
        let head_commit = head_commit.into();
        if name.trim().is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Extract,
                "branch.name",
                "must not be empty",
            ));
        }
        if head_commit == base.commit_id() {
            return Err(CodingAgentError::EmptyWorkProduct);
        }
        Ok(Self {
            name,
            head_commit,
            base,
        })
    }
}

/// Phase-4 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkProductRequest {
    pub run: CodingRunIdentity,
    pub workspace: MaterializedWorkspace,
    /// The commit the diff is taken against — normally the materialized pin.
    pub base: PinnedRef,
    pub max_inline_diff_bytes: u64,
}

impl WorkProductRequest {
    pub fn new(run: CodingRunIdentity, workspace: MaterializedWorkspace, base: PinnedRef) -> Self {
        Self {
            run,
            workspace,
            base,
            max_inline_diff_bytes: DEFAULT_MAX_INLINE_DIFF_BYTES,
        }
    }
}

/// The reviewable deliverable of one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkProduct {
    /// Derived under [`WORK_PRODUCT_ID_CONTRACT`]; never caller-assigned.
    product_id: String,
    pub run: CodingRunIdentity,
    pub repo: RepoCoordinates,
    pub base: PinnedRef,
    pub branch: Option<ProducedBranch>,
    pub diff: UnifiedDiff,
    pub stats: DiffStats,
    /// Advisory prose from the agent. Not the deliverable, and never a
    /// substitute for reading the diff.
    pub summary: Option<String>,
    pub extracted_at_unix: u64,
}

impl WorkProduct {
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        run: CodingRunIdentity,
        repo: RepoCoordinates,
        base: PinnedRef,
        branch: Option<ProducedBranch>,
        diff: UnifiedDiff,
        stats: DiffStats,
        summary: Option<String>,
        extracted_at_unix: u64,
    ) -> Result<Self, CodingAgentError> {
        if diff.byte_len() == 0 {
            return Err(CodingAgentError::EmptyWorkProduct);
        }
        if let Some(branch) = &branch {
            if branch.base.commit_id() != base.commit_id() {
                return Err(CodingAgentError::invalid(
                    CodingAgentPhase::Extract,
                    "branch.base",
                    "branch base must be the diff base",
                ));
            }
        }
        let product_id = derive_product_id(&run, &base, diff.digest());
        Ok(Self {
            product_id,
            run,
            repo,
            base,
            branch,
            diff,
            stats,
            summary,
            extracted_at_unix,
        })
    }

    pub fn product_id(&self) -> &str {
        &self.product_id
    }

    /// Whether this product belongs to `run_id`. Verified against the derived
    /// id, so a relabelled `run` field cannot fake attribution.
    pub fn attributed_to(&self, run_id: &str) -> bool {
        self.run.run_id == run_id
            && self.product_id == derive_product_id(&self.run, &self.base, self.diff.digest())
    }

    /// Re-derive the id from the current fields; a mismatch means the record
    /// was edited after extraction.
    pub fn id_is_consistent(&self) -> bool {
        self.product_id == derive_product_id(&self.run, &self.base, self.diff.digest())
    }
}

fn derive_product_id(run: &CodingRunIdentity, base: &PinnedRef, diff_digest: &str) -> String {
    opaque_reference_fingerprint(&format!(
        "{}|{}|{}|{}",
        run.tenant_id,
        run.run_id,
        base.commit_id(),
        diff_digest
    ))
}

#[cfg(test)]
#[path = "extract_test.rs"]
mod tests;
