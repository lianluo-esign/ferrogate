// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Atomic publication of an ordinary (non-presigned) inline asset
// push (issue #369). The former read-before-write + upsert let two concurrent
// FIRST pushes of the SAME `{tenant}/{type}/{name}/{version}[/variant]` both
// observe an absent row and overwrite each other -- last upsert wins on the
// metadata, and with bucket-backed inline storage both wrote the SAME
// deterministic object key so the winning metadata hash could reference the
// loser's bytes. This module gives the inline path the same publication
// invariant #338 gave the presigned path: bucket bytes land at a UNIQUE
// per-attempt candidate key, and metadata is published with the repository
// CREATE-IF-ABSENT primitive (never an immutable-version upsert). Exactly one
// concurrent first push becomes visible; losers get a typed 409 and clean ONLY
// their own unreferenced candidate; an outcome-unknown create preserves every
// candidate and never deletes a possibly-referenced winner.

use async_trait::async_trait;

use ferrogate_storage::{StorageError, StoredAsset};

use crate::state::AppState;

/// Best-effort sink for discarding an inline-publish CANDIDATE object -- the
/// unique bucket object a losing or definitively-failed publish attempt wrote
/// before the metadata create decided the winner. Abstracted behind a trait so
/// the winner/loser cleanup truth table is unit-testable with barriers and no
/// live bucket. A discard is always best-effort: a failed delete leaves an
/// orphan for the #263 GC reconciler, never data-loss of a referenced winner.
#[async_trait]
pub(super) trait AssetCandidateSink: Send + Sync {
    async fn discard_candidate(&self, key: &str);
}

/// Production sink: deletes the candidate object from the configured asset
/// bucket, best-effort.
pub(super) struct BucketCandidateSink {
    bucket: super::asset_bucket::AssetBucketClient,
}

impl BucketCandidateSink {
    pub(super) fn new(bucket: super::asset_bucket::AssetBucketClient) -> Self {
        Self { bucket }
    }
}

#[async_trait]
impl AssetCandidateSink for BucketCandidateSink {
    async fn discard_candidate(&self, key: &str) {
        if let Err(error) = self.bucket.delete_object(key).await {
            tracing::warn!(
                object_key = %key,
                error = %error,
                "failed to discard an inline-publish candidate object; it may be orphaned in the bucket"
            );
        }
    }
}

/// No-op sink for the pure-inline (no bucket) publish path: the bytes live in
/// the `stored_assets` row itself, so a losing attempt has no separate
/// candidate object to clean and the atomic row create is the whole invariant.
pub(super) struct NoCandidateSink;

#[async_trait]
impl AssetCandidateSink for NoCandidateSink {
    async fn discard_candidate(&self, _key: &str) {}
}

/// The two repository operations the atomic publication needs: the immutable
/// CREATE-IF-ABSENT (#338) and a winner re-read for loser reconciliation.
/// Abstracted behind a trait so the winner/loser/outcome-unknown truth table
/// can be driven with an injected registry (a definitive vs unknown create
/// error, a vanished/unreadable winner) without a live database.
#[async_trait]
pub(super) trait ImmutableAssetRegistry: Send + Sync {
    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError>;
    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError>;
}

#[async_trait]
impl ImmutableAssetRegistry for AppState {
    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError> {
        // Method-call syntax resolves to AppState's inherent method (inherent
        // wins over the trait method of the same name), not a recursive call.
        self.create_asset_if_absent(asset).await
    }

    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        self.get_asset(id)
            .await
            .map_err(|error| StorageError::Runtime(error.to_string()))
    }
}

/// The durable outcome of an inline publish attempt. The handler maps each
/// arm to a status/code; the mapping mirrors the presigned commit path so the
/// two publication surfaces agree on the truth table.
pub(super) enum InlinePublishOutcome {
    /// This attempt won the atomic create: its metadata + bytes are now the
    /// immutable version. -> 200.
    Published,
    /// A concurrent first push already published this version. This attempt's
    /// own candidate has been discarded (it was never the winner's). The
    /// version is immutable. -> typed 409 `asset_version_immutable`.
    Conflict,
    /// The create's durable outcome is unknown (its commit crossed the async
    /// timeout AFTER the commit fence). Every candidate is PRESERVED because
    /// the winner MAY be this attempt's row; retry the identical push before
    /// any cleanup. -> 503 `asset_commit_outcome_unknown`.
    OutcomeUnknown,
    /// A definitive pre-commit storage failure: nothing was published, so this
    /// attempt's own candidate has been discarded. -> 503 `storage_unavailable`.
    StorageFailed(String),
    /// The create reported a conflict but the winner could not be re-read (or
    /// vanished). The candidate is PRESERVED: an unreadable winner could
    /// theoretically reference it, and we never delete a possibly-referenced
    /// winner. -> 503 `storage_unavailable`.
    ReconcileFailed(String),
}

/// Whether a definitively-failed create lets us reclaim our own candidate.
/// Split out as a pure function so the "outcome-unknown never deletes"
/// invariant is directly unit-testable with a synthetic `StorageError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateDisposition {
    /// Definitive pre-commit failure -- discard our own candidate.
    DiscardOwn,
    /// Outcome-unknown (post-commit-fence loss) -- preserve every candidate.
    Preserve,
}

pub(super) fn candidate_disposition_for_create_error(error: &StorageError) -> CandidateDisposition {
    if matches!(error, StorageError::OperationCommitOutcomeUnknown { .. }) {
        CandidateDisposition::Preserve
    } else {
        CandidateDisposition::DiscardOwn
    }
}

/// True only when a losing attempt may discard its own candidate: the durable
/// winner must NOT reference that key. Since inline candidate keys are random
/// per attempt this is virtually always true, but the guard makes "never
/// delete a possibly-referenced winner" explicit rather than probabilistic.
pub(super) fn loser_may_discard_candidate(
    winner_storage_uri: Option<&str>,
    own_candidate_key: &str,
) -> bool {
    winner_storage_uri != Some(own_candidate_key)
}

/// Publish inline asset metadata atomically. The caller has already written the
/// bytes: to `candidate_key` in the bucket (bucket-backed inline storage) or
/// inline in `asset.content` (memory/Postgres bytes, `candidate_key == None`).
/// This performs the CREATE-IF-ABSENT publication and the winner/loser/unknown
/// cleanup truth table; it never issues an immutable-version upsert.
pub(super) async fn publish_inline_asset<R: ImmutableAssetRegistry + ?Sized>(
    registry: &R,
    sink: &dyn AssetCandidateSink,
    asset: StoredAsset,
    candidate_key: Option<&str>,
) -> InlinePublishOutcome {
    match registry.create_asset_if_absent(asset.clone()).await {
        Ok(true) => InlinePublishOutcome::Published,
        Ok(false) => {
            // Lost the atomic create: reconcile against the durable winner. We
            // may delete ONLY our own unreferenced candidate, never one the
            // winner references.
            match registry.get_asset(&asset.id).await {
                Ok(Some(winner)) => {
                    if let Some(key) = candidate_key {
                        if loser_may_discard_candidate(winner.storage_uri.as_deref(), key) {
                            sink.discard_candidate(key).await;
                        }
                    }
                    InlinePublishOutcome::Conflict
                }
                Ok(None) => {
                    // The winner disappeared between the create and this reread
                    // (a concurrent delete). Our candidate is provably
                    // unreferenced now, so it is safe to reclaim.
                    if let Some(key) = candidate_key {
                        sink.discard_candidate(key).await;
                    }
                    InlinePublishOutcome::ReconcileFailed(
                        "the conflicting asset disappeared before it could be reconciled"
                            .to_string(),
                    )
                }
                Err(error) => {
                    // Winner unreadable: preserve the candidate (fail safe --
                    // never delete a possibly-referenced winner).
                    InlinePublishOutcome::ReconcileFailed(error.to_string())
                }
            }
        }
        Err(error) => match candidate_disposition_for_create_error(&error) {
            CandidateDisposition::Preserve => InlinePublishOutcome::OutcomeUnknown,
            CandidateDisposition::DiscardOwn => {
                if let Some(key) = candidate_key {
                    sink.discard_candidate(key).await;
                }
                InlinePublishOutcome::StorageFailed(error.to_string())
            }
        },
    }
}

/// Derive a UNIQUE bucket object key for one inline publish attempt so two
/// concurrent first pushes of the same version can never overwrite each other's
/// bytes. The former key was the bare `asset_id`, which two concurrent pushes
/// shared and clobbered; the key now keeps that `asset_id` as a readable prefix
/// (unchanged ownership/GC grouping, and the internal object was never exposed
/// to clients) and appends a 128-bit random suffix for per-attempt uniqueness.
/// The winning metadata therefore references only the bytes THIS attempt wrote.
pub(super) fn inline_candidate_object_key(asset_id: &str) -> anyhow::Result<String> {
    Ok(format!("{asset_id}/inline_{}", random_hex_128()?))
}

fn random_hex_128() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("operating-system random source unavailable: {error}"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

#[cfg(test)]
#[path = "asset_inline_publish_test.rs"]
mod asset_inline_publish_test;
