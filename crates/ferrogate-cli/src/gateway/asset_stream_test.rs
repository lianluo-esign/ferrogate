// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Tests for the bounded-memory asset verification/copy pass
// (issue #259). These pin the two properties the streaming commit path is
// worth having: it computes the SAME sha256 and the SAME malware verdict a
// whole-buffer pass would, for every chunk split -- and it does so with
// resident state that does not grow with the object.

use std::sync::Mutex;

use bytes::Bytes;
use ferrogate_storage::sha256_hex;

use super::{
    copy_object_with_incremental_screen, StreamedCopy, StreamingObjectScreen, SCREEN_CARRY_BYTES,
};
use crate::gateway::asset_bucket::{AssetObjectStore, ObjectByteStream, PresignedUpload};
use crate::gateway::asset_scan::EICAR_TEST_SIGNATURE;

/// An in-memory object store that serves reads as a *chunk stream* and records
/// what a streamed PUT actually received. Only the streaming methods are real;
/// everything else is out of this module's scope and says so.
#[derive(Default)]
struct FakeStreamingStore {
    objects: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Bytes per chunk the read stream yields, to exercise boundary handling.
    chunk_size: usize,
    /// Everything a streamed PUT declared and everything it actually carried.
    puts: Mutex<Vec<RecordedPut>>,
    /// When set, `put_object_stream` drains the body and then fails, standing
    /// in for a bucket that refuses a payload contradicting the signed hash.
    refuse_put: bool,
}

impl FakeStreamingStore {
    fn with_object(key: &str, bytes: &[u8], chunk_size: usize) -> Self {
        let store = Self {
            chunk_size,
            ..Self::default()
        };
        store
            .objects
            .lock()
            .unwrap()
            .insert(key.to_string(), bytes.to_vec());
        store
    }
}

/// One streamed PUT as the destination saw it.
#[derive(Debug)]
struct RecordedPut {
    key: String,
    content_type: String,
    declared_length: u64,
    declared_sha256: String,
    received: Vec<u8>,
}

fn unsupported(operation: &str) -> anyhow::Error {
    anyhow::anyhow!("FakeStreamingStore does not implement {operation}")
}

#[async_trait::async_trait]
impl AssetObjectStore for FakeStreamingStore {
    async fn put_object(
        &self,
        _key: &str,
        _body: &[u8],
        _content_type: &str,
    ) -> anyhow::Result<()> {
        Err(unsupported("put_object"))
    }
    async fn put_object_owned(
        &self,
        _key: &str,
        _body: Vec<u8>,
        _content_type: &str,
    ) -> anyhow::Result<()> {
        Err(unsupported("put_object_owned"))
    }
    async fn get_object(&self, _key: &str, _max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        Err(unsupported("get_object"))
    }
    async fn get_object_if_present(
        &self,
        _key: &str,
        _max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Err(unsupported("get_object_if_present"))
    }
    async fn get_object_stream(&self, key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
        let Some(bytes) = self.objects.lock().unwrap().get(key).cloned() else {
            return Ok(None);
        };
        let chunk_size = self.chunk_size.max(1);
        let chunks: Vec<anyhow::Result<Bytes>> = bytes
            .chunks(chunk_size)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect();
        Ok(Some(Box::pin(futures_util::stream::iter(chunks))))
    }
    async fn put_object_stream(
        &self,
        key: &str,
        content_type: &str,
        content_length: u64,
        content_sha256_hex: &str,
        mut body: ObjectByteStream,
    ) -> anyhow::Result<()> {
        use futures_util::StreamExt;
        let mut received = Vec::new();
        while let Some(chunk) = body.next().await {
            received.extend_from_slice(&chunk?);
        }
        self.puts.lock().unwrap().push(RecordedPut {
            key: key.to_string(),
            content_type: content_type.to_string(),
            declared_length: content_length,
            declared_sha256: content_sha256_hex.to_string(),
            received: received.clone(),
        });
        if self.refuse_put {
            anyhow::bail!("bucket refused the payload (HTTP 400): checksum mismatch");
        }
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), received);
        Ok(())
    }
    async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
    async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .map(|bytes| bytes.len() as u64))
    }
    async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        Err(unsupported("list_objects"))
    }
    fn presign_put(
        &self,
        _key: &str,
        _expires_secs: u64,
        _timestamp_unix: u64,
        _size_bytes: u64,
        _content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        Err(unsupported("presign_put"))
    }
    fn presign_get(
        &self,
        _key: &str,
        _expires_secs: u64,
        _timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        Err(unsupported("presign_get"))
    }
}

fn screen_in_chunks(bytes: &[u8], chunk_size: usize) -> super::StreamedObjectVerdict {
    let mut screen = StreamingObjectScreen::new();
    for chunk in bytes.chunks(chunk_size.max(1)) {
        screen.update(chunk);
    }
    screen.verdict()
}

#[test]
fn incremental_sha256_matches_the_one_shot_hash_for_every_chunk_split() {
    // The streaming path replaces `sha256_hex(&whole_object)`. If the two ever
    // disagreed, a legitimate upload would be rejected as tampered (or worse).
    let mut payload = Vec::new();
    for index in 0_u32..5_000 {
        payload.extend_from_slice(&index.to_le_bytes());
    }
    let expected = sha256_hex(&payload);
    for chunk_size in [1, 7, 64, 4096, payload.len(), payload.len() * 2] {
        let verdict = screen_in_chunks(&payload, chunk_size);
        assert_eq!(
            verdict.sha256, expected,
            "chunk size {chunk_size} produced a different digest"
        );
        assert_eq!(verdict.size_bytes, payload.len() as u64);
        assert!(!verdict.eicar_found);
    }
    // The empty object is the degenerate case the one-shot hash also has to
    // agree on.
    assert_eq!(screen_in_chunks(&[], 4096).sha256, sha256_hex(b""));
}

#[test]
fn a_malware_signature_split_across_chunk_boundaries_is_still_found() {
    // The whole reason the screen carries a window: `contains_eicar` over each
    // chunk in isolation misses any signature that straddles a boundary, which
    // an uploader controls exactly by choosing its transfer chunking.
    let mut payload = vec![b'a'; 1024];
    payload.extend_from_slice(EICAR_TEST_SIGNATURE);
    payload.extend_from_slice(&[b'b'; 1024]);

    // One byte at a time is the worst case: no single chunk ever contains more
    // than one byte of the signature.
    for chunk_size in [1, 2, 13, 67, 68, 69, 512, payload.len()] {
        assert!(
            screen_in_chunks(&payload, chunk_size).eicar_found,
            "chunk size {chunk_size} missed a boundary-straddling signature"
        );
    }
    // A signature at the very start and at the very end are both matched.
    assert!(screen_in_chunks(EICAR_TEST_SIGNATURE, 3).eicar_found);
    // Clean content stays clean -- the carry must not manufacture matches.
    assert!(!screen_in_chunks(&vec![b'a'; 8192], 7).eicar_found);
}

#[test]
fn screening_state_does_not_grow_with_the_object() {
    // The bound this module exists for: peak resident screening state is a
    // fixed carry window, not a function of object size. A regression that
    // reintroduced whole-object buffering (e.g. accumulating chunks to hash at
    // the end) would blow this assertion at the first megabyte.
    let mut screen = StreamingObjectScreen::new();
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..128 {
        screen.update(&chunk);
        assert!(
            screen.carry.len() <= SCREEN_CARRY_BYTES,
            "carry grew to {} bytes",
            screen.carry.len()
        );
    }
    assert_eq!(screen.verdict().size_bytes, 8 * 1024 * 1024);
}

#[test]
fn a_failed_source_never_reports_a_match_even_when_its_prefix_would() {
    // The pathological case: a transfer that dies after delivering exactly as
    // many bytes as the intent declared, whose prefix happens to hash to the
    // declared digest. Length+digest alone would call that a match; the
    // failure flag is what stops a torn read from publishing.
    let mut clean = StreamingObjectScreen::new();
    clean.update(b"abcd");
    assert!(clean.verdict().matches(4, &sha256_hex(b"abcd")));

    let mut failed = StreamingObjectScreen::new();
    failed.update(b"abcd");
    failed.mark_source_failed();
    let verdict = failed.verdict();
    assert!(verdict.source_failed);
    assert!(
        !verdict.matches(4, &sha256_hex(b"abcd")),
        "a stream that errored must never be reported as a match"
    );
    // A short read is caught by the length check on its own.
    let mut short = StreamingObjectScreen::new();
    short.update(b"ab");
    assert!(!short.verdict().matches(4, &sha256_hex(b"abcd")));
}

#[tokio::test]
async fn the_copy_forwards_the_exact_bytes_and_reports_its_own_verdict() {
    let payload: Vec<u8> = (0..300_000_u32).map(|index| index as u8).collect();
    let sha = sha256_hex(&payload);
    let store = FakeStreamingStore::with_object("staging/a", &payload, 8 * 1024);

    let copy = copy_object_with_incremental_screen(
        &store,
        "staging/a",
        "final/a",
        payload.len() as u64,
        &sha,
        "application/octet-stream",
    )
    .await
    .expect("copy runs");

    let StreamedCopy::Copied(verdict) = copy else {
        panic!("expected a completed copy");
    };
    assert_eq!(verdict.sha256, sha);
    assert_eq!(verdict.size_bytes, payload.len() as u64);
    assert!(verdict.matches(payload.len() as u64, &sha));

    let puts = store.puts.lock().unwrap();
    assert_eq!(puts.len(), 1);
    let put = &puts[0];
    assert_eq!(put.key, "final/a");
    assert_eq!(put.content_type, "application/octet-stream");
    assert_eq!(put.declared_length, payload.len() as u64);
    assert_eq!(put.declared_sha256, sha);
    assert_eq!(
        put.received, payload,
        "the copy must forward the exact bytes"
    );
}

#[tokio::test]
async fn a_staged_object_that_contradicts_the_intent_is_reported_as_a_mismatch() {
    // The bucket stores different bytes than the intent declared (a tampered
    // or replayed direct PUT). The gateway's own accounting -- not the
    // bucket's acceptance -- must be what refuses it.
    let staged = b"the bytes actually uploaded".to_vec();
    let declared = sha256_hex(b"the bytes the client claimed");
    let store = FakeStreamingStore::with_object("staging/b", &staged, 4);

    let copy = copy_object_with_incremental_screen(
        &store,
        "staging/b",
        "final/b",
        staged.len() as u64,
        &declared,
        "text/plain",
    )
    .await
    .expect("copy runs");

    let StreamedCopy::Copied(verdict) = copy else {
        panic!("expected a completed copy with a failing verdict");
    };
    assert_eq!(verdict.sha256, sha256_hex(&staged));
    assert!(
        !verdict.matches(staged.len() as u64, &declared),
        "the verdict must not match a payload that contradicts the intent"
    );
}

#[tokio::test]
async fn a_bucket_refusal_over_mismatched_bytes_is_a_content_rejection_not_a_503() {
    // A real S3-compatible bucket recomputes `x-amz-content-sha256` and refuses
    // a payload that contradicts it. That refusal is a transport error, but the
    // gateway corroborated the mismatch byte-by-byte, so it must surface as a
    // content rejection (422) rather than an infrastructure failure (503).
    let staged = b"the bytes actually uploaded".to_vec();
    let declared = sha256_hex(b"the bytes the client claimed");
    let mut store = FakeStreamingStore::with_object("staging/c", &staged, 4);
    store.refuse_put = true;

    let copy = copy_object_with_incremental_screen(
        &store,
        "staging/c",
        "final/c",
        staged.len() as u64,
        &declared,
        "text/plain",
    )
    .await
    .expect("a corroborated mismatch is not an outer error");
    assert!(matches!(copy, StreamedCopy::RejectedByPayloadMismatch(_)));
}

#[tokio::test]
async fn a_bucket_refusal_over_matching_bytes_stays_an_infrastructure_failure() {
    // The other half of the same rule: when our accounting AGREES with the
    // intent, a PUT failure is the bucket's problem and must not be laundered
    // into a client-facing "your object is invalid".
    let staged = b"perfectly valid bytes".to_vec();
    let sha = sha256_hex(&staged);
    let mut store = FakeStreamingStore::with_object("staging/d", &staged, 4);
    store.refuse_put = true;

    let error = copy_object_with_incremental_screen(
        &store,
        "staging/d",
        "final/d",
        staged.len() as u64,
        &sha,
        "text/plain",
    )
    .await
    .expect_err("a bucket failure over valid bytes must stay an error");
    assert!(error.to_string().contains("bucket refused"));
}

#[tokio::test]
async fn a_missing_staging_object_is_reported_as_absent_not_as_an_error() {
    let store = FakeStreamingStore::default();
    let copy = copy_object_with_incremental_screen(
        &store,
        "staging/missing",
        "final/missing",
        10,
        &sha256_hex(b"whatever"),
        "text/plain",
    )
    .await
    .expect("an absent source is a normal outcome");
    assert!(matches!(copy, StreamedCopy::SourceMissing));
    assert!(
        store.puts.lock().unwrap().is_empty(),
        "nothing may be written when there is nothing to copy"
    );
}
