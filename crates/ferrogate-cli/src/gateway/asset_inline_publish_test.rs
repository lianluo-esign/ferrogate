// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Concurrency + truth-table coverage for the atomic inline asset
// publication (#369). Barrier/channel driven (no timing sleeps): two concurrent
// FIRST pushes of the same version yield exactly one visible winner + one typed
// 409, the winner's bytes match its metadata hash, and a loser cleans ONLY its
// own unreferenced candidate. Every create-result arm of the truth table
// (winner/conflict/outcome-unknown/definitive-failure/vanished/unreadable) is
// proven with an injected registry so no live database is needed.

use super::*;

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Barrier, Mutex};
use std::thread;

use async_trait::async_trait;
use ferrogate_storage::sha256_hex;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

const VERSION_ID: &str = "tenant-a:cli_tool:hello:1.0.0";

/// A bucket-backed inline asset row: the bytes live in the bucket at
/// `storage_uri`, `content` is empty, and `content_hash` is the sha256 of the
/// bytes (exactly the shape `handle_asset_push` builds for a bucket-backed
/// push).
fn bucket_asset(bytes: &[u8], storage_key: &str) -> StoredAsset {
    StoredAsset {
        id: VERSION_ID.into(),
        tenant_id: "tenant-a".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "hello".into(),
        version: "1.0.0".into(),
        content_type: "application/octet-stream".into(),
        content_hash: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
        content: Vec::new(),
        storage_uri: Some(storage_key.to_string()),
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

/// An in-memory stand-in for the asset bucket: it holds every candidate
/// object's bytes and records which candidates were discarded, so a test can
/// prove the winner's bytes survive and the loser's candidate was reclaimed --
/// without touching a live bucket.
#[derive(Default)]
struct RecordingBucket {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    discarded: Mutex<Vec<String>>,
}

impl RecordingBucket {
    fn put(&self, key: &str, bytes: Vec<u8>) {
        self.objects.lock().unwrap().insert(key.to_string(), bytes);
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    fn was_discarded(&self, key: &str) -> bool {
        self.discarded.lock().unwrap().iter().any(|k| k == key)
    }
}

#[async_trait]
impl AssetCandidateSink for RecordingBucket {
    async fn discard_candidate(&self, key: &str) {
        self.objects.lock().unwrap().remove(key);
        self.discarded.lock().unwrap().push(key.to_string());
    }
}

/// A scripted registry so every create-result arm is directly exercisable,
/// including the ones an in-memory backend can never produce on its own
/// (outcome-unknown, a vanished or unreadable winner).
enum CreateScript {
    Conflict,
    OverQuota,
    Unknown,
    Definitive,
}

struct FakeRegistry {
    create: CreateScript,
    winner: Option<StoredAsset>,
    get_fails: bool,
}

#[async_trait]
impl ImmutableAssetRegistry for FakeRegistry {
    async fn create_asset_within_quota(
        &self,
        _asset: StoredAsset,
        _quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        match self.create {
            CreateScript::Conflict => Ok(AssetQuotaAdmission::AlreadyExists),
            CreateScript::OverQuota => Ok(AssetQuotaAdmission::OverQuota {
                used_bytes: 90,
                attempted_bytes: 20,
                quota_bytes: 100,
            }),
            CreateScript::Unknown => Err(StorageError::OperationCommitOutcomeUnknown {
                operation: "create asset within quota",
                stage: "transaction commit",
            }),
            CreateScript::Definitive => Err(StorageError::Postgres("statement failed".into())),
        }
    }

    async fn get_asset(&self, _id: &str) -> Result<Option<StoredAsset>, StorageError> {
        if self.get_fails {
            return Err(StorageError::Runtime("winner unreadable".into()));
        }
        Ok(self.winner.clone())
    }
}

fn is_published(outcome: &InlinePublishOutcome) -> bool {
    matches!(outcome, InlinePublishOutcome::Published)
}

fn is_conflict(outcome: &InlinePublishOutcome) -> bool {
    matches!(outcome, InlinePublishOutcome::Conflict)
}

// -------- Concurrency proofs against the real in-memory registry --------

/// The core acceptance: two concurrent FIRST pushes of the SAME version with
/// DIFFERENT content resolve to exactly one visible winner + one typed 409, the
/// winner's bytes match its metadata hash, and the loser reclaimed only its own
/// candidate while the winner's object is untouched. Barrier-synchronized, no
/// timing sleeps.
#[test]
fn concurrent_different_content_first_pushes_have_exactly_one_winner() {
    let state = AppState::new(ferrogate_config::Config::default());
    let bucket = Arc::new(RecordingBucket::default());
    let barrier = Arc::new(Barrier::new(3));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for (tag, fill) in [("a", 0xAA_u8), ("b", 0xBB_u8)] {
        let state = state.clone();
        let bucket = Arc::clone(&bucket);
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let bytes = vec![fill; 48];
            let key = format!(".ferrogate/objects/pfx/inline_{tag}");
            let asset = bucket_asset(&bytes, &key);
            // Simulate the per-attempt bucket PUT that precedes publication.
            bucket.put(&key, bytes.clone());
            barrier.wait();
            let outcome = block_on(publish_inline_asset(
                &state,
                &*bucket,
                asset,
                Some(key.as_str()),
                None,
            ));
            tx.send((key, outcome)).expect("report outcome");
        }));
    }
    drop(tx);
    barrier.wait();

    let results: Vec<(String, InlinePublishOutcome)> = rx.into_iter().collect();
    for handle in handles {
        handle.join().expect("publish worker");
    }

    assert_eq!(
        results.iter().filter(|(_, o)| is_published(o)).count(),
        1,
        "exactly one concurrent first push may become visible"
    );
    assert_eq!(
        results.iter().filter(|(_, o)| is_conflict(o)).count(),
        1,
        "the losing push must get a typed conflict, not a silent overwrite"
    );

    let winner_key = results
        .iter()
        .find_map(|(key, o)| is_published(o).then(|| key.clone()))
        .expect("one winner key");
    let loser_key = results
        .iter()
        .find_map(|(key, o)| is_conflict(o).then(|| key.clone()))
        .expect("one loser key");

    let winner_row = block_on(state.get_asset(VERSION_ID))
        .expect("read winner")
        .expect("winner row exists");
    assert_eq!(
        winner_row.storage_uri.as_deref(),
        Some(winner_key.as_str()),
        "the visible row references the winner's own candidate object"
    );
    let winner_bytes = bucket
        .get(&winner_key)
        .expect("winner's candidate object survives");
    assert_eq!(
        sha256_hex(&winner_bytes),
        winner_row.content_hash,
        "the winner's stored bytes match its published metadata hash"
    );
    assert!(
        bucket.get(&loser_key).is_none(),
        "the loser reclaimed its own unreferenced candidate"
    );
    assert!(
        bucket.was_discarded(&loser_key) && !bucket.was_discarded(&winner_key),
        "cleanup touched ONLY the loser's candidate, never the winner's"
    );
}

/// Same-content concurrent first pushes still resolve to exactly one winner +
/// one 409 (inline publication has no upload-id idempotency key, so a second
/// racing push is a distinct attempt). Each attempt writes its own unique
/// candidate, so the loser still cleans only its own and the winner's bytes
/// remain hash-consistent.
#[test]
fn concurrent_same_content_first_pushes_have_exactly_one_winner() {
    let state = AppState::new(ferrogate_config::Config::default());
    let bucket = Arc::new(RecordingBucket::default());
    let barrier = Arc::new(Barrier::new(3));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    let shared = vec![0x5A_u8; 64];
    for tag in ["a", "b"] {
        let state = state.clone();
        let bucket = Arc::clone(&bucket);
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        let bytes = shared.clone();
        handles.push(thread::spawn(move || {
            let key = format!(".ferrogate/objects/pfx/inline_{tag}");
            let asset = bucket_asset(&bytes, &key);
            bucket.put(&key, bytes.clone());
            barrier.wait();
            let outcome = block_on(publish_inline_asset(
                &state,
                &*bucket,
                asset,
                Some(key.as_str()),
                None,
            ));
            tx.send((key, outcome)).expect("report outcome");
        }));
    }
    drop(tx);
    barrier.wait();

    let results: Vec<(String, InlinePublishOutcome)> = rx.into_iter().collect();
    for handle in handles {
        handle.join().expect("publish worker");
    }

    assert_eq!(results.iter().filter(|(_, o)| is_published(o)).count(), 1);
    assert_eq!(results.iter().filter(|(_, o)| is_conflict(o)).count(), 1);

    let winner_row = block_on(state.get_asset(VERSION_ID))
        .expect("read winner")
        .expect("winner row exists");
    let winner_key = winner_row
        .storage_uri
        .clone()
        .expect("bucket-backed winner");
    let winner_bytes = bucket.get(&winner_key).expect("winner object survives");
    assert_eq!(sha256_hex(&winner_bytes), winner_row.content_hash);

    let loser_key = results
        .iter()
        .find_map(|(key, o)| is_conflict(o).then(|| key.clone()))
        .expect("loser key");
    assert!(
        bucket.get(&loser_key).is_none(),
        "the same-content loser still reclaims only its own candidate"
    );
}

/// A deterministic loser (winner already published) must reclaim only its own
/// candidate and leave the winner's object and metadata untouched.
#[test]
fn loser_reclaims_only_its_own_candidate_against_a_seeded_winner() {
    let state = AppState::new(ferrogate_config::Config::default());
    let bucket = RecordingBucket::default();

    let winner_bytes = vec![1_u8; 32];
    let winner_key = ".ferrogate/objects/pfx/inline_winner";
    let winner = bucket_asset(&winner_bytes, winner_key);
    bucket.put(winner_key, winner_bytes.clone());
    assert!(
        block_on(state.create_asset_within_quota(winner.clone(), None)).expect("seed winner")
            == AssetQuotaAdmission::Admitted,
        "the seeded winner publishes"
    );

    let loser_bytes = vec![2_u8; 32];
    let loser_key = ".ferrogate/objects/pfx/inline_loser";
    let loser = bucket_asset(&loser_bytes, loser_key);
    bucket.put(loser_key, loser_bytes);

    let outcome = block_on(publish_inline_asset(
        &state,
        &bucket,
        loser,
        Some(loser_key),
        None,
    ));
    assert!(is_conflict(&outcome), "the second push is a typed conflict");
    assert!(
        bucket.get(loser_key).is_none() && bucket.was_discarded(loser_key),
        "the loser reclaimed its own candidate"
    );
    assert_eq!(
        bucket.get(winner_key),
        Some(winner_bytes),
        "the winner's bytes are never deleted by a loser"
    );
    assert_eq!(
        block_on(state.get_asset(VERSION_ID))
            .expect("read winner")
            .expect("winner exists"),
        winner,
        "the losing publish never mutated the winner's metadata"
    );
}

// -------- Truth-table arms via an injected registry --------

/// An outcome-unknown create (commit crossed the async-timeout fence) must
/// PRESERVE the candidate and never delete a possibly-referenced winner.
#[test]
fn outcome_unknown_create_preserves_the_candidate() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_unknown";
    bucket.put(key, vec![9_u8; 8]);
    let registry = FakeRegistry {
        create: CreateScript::Unknown,
        winner: None,
        get_fails: false,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[9_u8; 8], key),
        Some(key),
        None,
    ));
    assert!(matches!(outcome, InlinePublishOutcome::OutcomeUnknown));
    assert!(
        bucket.get(key).is_some() && !bucket.was_discarded(key),
        "an unknown outcome must never delete a possibly-committed winner's bytes"
    );
}

/// A definitive pre-commit failure publishes nothing, so the attempt reclaims
/// its own candidate.
#[test]
fn definitive_create_failure_reclaims_its_own_candidate() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_definitive";
    bucket.put(key, vec![3_u8; 8]);
    let registry = FakeRegistry {
        create: CreateScript::Definitive,
        winner: None,
        get_fails: false,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[3_u8; 8], key),
        Some(key),
        None,
    ));
    assert!(matches!(outcome, InlinePublishOutcome::StorageFailed(_)));
    assert!(
        bucket.get(key).is_none() && bucket.was_discarded(key),
        "a definitive failure reclaims its own unreferenced candidate"
    );
}

/// An over-quota admission (#371) is a definitive pre-commit rejection: nothing
/// was reserved or published, so the attempt reclaims its OWN unreferenced
/// candidate and surfaces the typed over-quota outcome with the observed usage.
#[test]
fn over_quota_admission_reclaims_its_own_candidate() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_overquota";
    bucket.put(key, vec![6_u8; 8]);
    let registry = FakeRegistry {
        create: CreateScript::OverQuota,
        winner: None,
        get_fails: false,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[6_u8; 8], key),
        Some(key),
        Some(100),
    ));
    assert!(matches!(
        outcome,
        InlinePublishOutcome::OverQuota {
            used_bytes: 90,
            attempted_bytes: 20,
            quota_bytes: 100,
        }
    ));
    assert!(
        bucket.get(key).is_none() && bucket.was_discarded(key),
        "an over-quota rejection reclaims its own unreferenced candidate"
    );
}

/// A loser whose winner (impossibly) references the loser's own key must NOT
/// delete it -- the guard makes "never delete a possibly-referenced winner"
/// explicit rather than probabilistic.
#[test]
fn loser_never_deletes_a_candidate_the_winner_references() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_shared";
    bucket.put(key, vec![7_u8; 8]);
    let winner = bucket_asset(&[7_u8; 8], key);
    let registry = FakeRegistry {
        create: CreateScript::Conflict,
        winner: Some(winner),
        get_fails: false,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[7_u8; 8], key),
        Some(key),
        None,
    ));
    assert!(is_conflict(&outcome));
    assert!(
        bucket.get(key).is_some() && !bucket.was_discarded(key),
        "a candidate the winner references must never be discarded"
    );
}

/// A conflict whose winner vanished before reread: the candidate is provably
/// unreferenced, so it is reclaimed and the outcome is a reconcile failure.
#[test]
fn conflict_with_a_vanished_winner_reclaims_the_candidate() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_vanished";
    bucket.put(key, vec![4_u8; 8]);
    let registry = FakeRegistry {
        create: CreateScript::Conflict,
        winner: None,
        get_fails: false,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[4_u8; 8], key),
        Some(key),
        None,
    ));
    assert!(matches!(outcome, InlinePublishOutcome::ReconcileFailed(_)));
    assert!(bucket.get(key).is_none() && bucket.was_discarded(key));
}

/// A conflict whose winner is unreadable: preserve the candidate (fail safe).
#[test]
fn conflict_with_an_unreadable_winner_preserves_the_candidate() {
    let bucket = RecordingBucket::default();
    let key = ".ferrogate/objects/pfx/inline_unreadable";
    bucket.put(key, vec![5_u8; 8]);
    let registry = FakeRegistry {
        create: CreateScript::Conflict,
        winner: None,
        get_fails: true,
    };
    let outcome = block_on(publish_inline_asset(
        &registry,
        &bucket,
        bucket_asset(&[5_u8; 8], key),
        Some(key),
        None,
    ));
    assert!(matches!(outcome, InlinePublishOutcome::ReconcileFailed(_)));
    assert!(
        bucket.get(key).is_some() && !bucket.was_discarded(key),
        "an unreadable winner might reference our key -- preserve it"
    );
}

/// The pure-inline (no bucket) path passes `None` for the candidate: the
/// winner's bytes live in the row and a loser has nothing to clean.
#[test]
fn pure_inline_publish_has_no_candidate_to_clean() {
    let state = AppState::new(ferrogate_config::Config::default());
    let sink = NoCandidateSink;

    let mut winner = bucket_asset(&[1_u8; 4], "");
    winner.storage_uri = None;
    winner.content = vec![1_u8; 4];
    let winner_outcome = block_on(publish_inline_asset(
        &state,
        &sink,
        winner.clone(),
        None,
        None,
    ));
    assert!(is_published(&winner_outcome));

    let mut loser = bucket_asset(&[2_u8; 4], "");
    loser.storage_uri = None;
    loser.content = vec![2_u8; 4];
    let loser_outcome = block_on(publish_inline_asset(&state, &sink, loser, None, None));
    assert!(is_conflict(&loser_outcome));

    let stored = block_on(state.get_asset(VERSION_ID))
        .expect("read winner")
        .expect("winner exists");
    assert_eq!(
        sha256_hex(&stored.content),
        stored.content_hash,
        "the pure-inline winner's row bytes match its hash"
    );
    assert_eq!(stored, winner, "the loser never mutated the winner row");
}

// -------- Pure helpers --------

#[test]
fn candidate_disposition_preserves_only_outcome_unknown() {
    assert_eq!(
        candidate_disposition_for_create_error(&StorageError::OperationCommitOutcomeUnknown {
            operation: "create asset if absent",
            stage: "transaction commit",
        }),
        CandidateDisposition::Preserve
    );
    assert_eq!(
        candidate_disposition_for_create_error(&StorageError::Postgres("boom".into())),
        CandidateDisposition::DiscardOwn
    );
    assert_eq!(
        candidate_disposition_for_create_error(&StorageError::OperationDeadlineExceeded {
            operation: "create asset if absent",
            stage: "asset insert",
            commit_started: false,
        }),
        CandidateDisposition::DiscardOwn
    );
}

#[test]
fn loser_may_discard_only_when_the_winner_does_not_reference_the_key() {
    assert!(loser_may_discard_candidate(Some("other-key"), "mine"));
    assert!(loser_may_discard_candidate(None, "mine"));
    assert!(!loser_may_discard_candidate(Some("mine"), "mine"));
}

#[test]
fn inline_candidate_keys_are_unique_per_attempt_and_grouped_per_asset() {
    let a = inline_candidate_object_key(VERSION_ID).expect("key a");
    let b = inline_candidate_object_key(VERSION_ID).expect("key b");
    assert_ne!(a, b, "each attempt gets a unique candidate key");
    // The asset id stays a readable prefix (unchanged ownership/GC grouping and
    // the storage_uri contract that surfaces the id) with a unique suffix.
    let prefix = format!("{VERSION_ID}/inline_");
    assert!(a.starts_with(&prefix) && b.starts_with(&prefix));
    // A different asset id lands under a different prefix.
    let other = inline_candidate_object_key("tenant-a:cli_tool:hello:2.0.0").expect("key other");
    assert!(!other.starts_with(&prefix));
}
