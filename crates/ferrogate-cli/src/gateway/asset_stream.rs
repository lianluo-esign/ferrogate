// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Bounded-memory verification + copy for the large-file asset
// path (issue #259).
//
// The presigned *data* path already bypasses the gateway: the client PUTs and
// GETs object bytes directly against the bucket. The **commit** leg did not.
// It called `get_object_if_present` (`response.bytes().await?.to_vec()` -- the
// whole object into a `Vec`), one-shot hashed that buffer, screened it, and
// re-PUT it whole to the private final key. Peak RSS per commit was therefore
// ~= the object size, bounded only by `asset_presign_max_object_bytes`
// (default 5 GiB) with no cap on concurrent commits: N concurrent large
// commits were an OOM/DoS on the Pingora process, and the
// "streams straight to the bucket so bytes never buffer in the gateway"
// claim in `assets.rs` was false for exactly this leg.
//
// This module replaces that with a single bounded pass. The staged object is
// streamed chunk by chunk; each chunk feeds an incremental SHA-256 and an
// incremental content screen, and the *same* chunk is handed straight to the
// final PUT's request body. Resident bytes are one HTTP chunk plus a 67-byte
// carry window, independent of object size.
//
// Fail-closed publication is preserved, and is the reason the copy target is
// safe to write before the verdict is known: the final key is a fresh
// `obj_<128-bit-random>` under an intent-derived prefix that nothing can
// reference until `create_asset_within_quota` publishes the row. A mismatch
// therefore deletes the final candidate *and* the staging object and returns
// the same 422 the buffered path returns -- no `stored_assets` row is ever
// created for unverified bytes.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use sha2::{Digest, Sha256};

use super::asset_bucket::{AssetObjectStore, ObjectByteStream};
use super::asset_scan::EICAR_TEST_SIGNATURE;

/// Bytes retained between chunks so a malware signature straddling a chunk
/// boundary is still matched: one less than the pattern length is exactly the
/// longest possible prefix of a match that can end a chunk.
const SCREEN_CARRY_BYTES: usize = EICAR_TEST_SIGNATURE.len() - 1;

/// The incremental counterpart of `sha256_hex` + `asset_scan::contains_eicar`:
/// everything the commit path can decide from a byte stream without holding
/// the stream.
#[derive(Debug)]
pub(super) struct StreamingObjectScreen {
    hasher: Sha256,
    bytes_seen: u64,
    eicar_found: bool,
    /// Tail of the previous chunk, at most [`SCREEN_CARRY_BYTES`] long.
    carry: Vec<u8>,
    /// The source stream yielded an error part-way through.
    ///
    /// Tracked instead of "did we see EOF?" for a concrete reason: the
    /// destination PUT declares `Content-Length`, so hyper stops polling the
    /// body the moment that many bytes have been written and the source's
    /// `None` is never observed on the happy path. Byte-count-plus-digest is
    /// the completeness proof (a truncated source cannot produce the declared
    /// digest over the declared length); this flag exists only so a transport
    /// failure's *partial* accounting is never read as a content verdict.
    source_failed: bool,
}

impl Default for StreamingObjectScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingObjectScreen {
    pub(super) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_seen: 0,
            eicar_found: false,
            carry: Vec::with_capacity(SCREEN_CARRY_BYTES),
            source_failed: false,
        }
    }

    /// Folds one chunk in. Resident state after the call is bounded by
    /// [`SCREEN_CARRY_BYTES`]; the chunk itself is never retained.
    pub(super) fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.bytes_seen = self.bytes_seen.saturating_add(chunk.len() as u64);
        if !self.eicar_found {
            // Two scans cover every possible match position. A match lying
            // wholly inside this chunk is found by the second. A match that
            // starts before this chunk must start within the retained carry
            // (the last SCREEN_CARRY_BYTES bytes of the stream so far) and can
            // extend at most SCREEN_CARRY_BYTES bytes into this one, so the
            // boundary window catches it -- including a signature dribbled
            // across many one-byte chunks, because the carry spans chunks
            // rather than resetting per chunk.
            if !self.carry.is_empty() {
                let head = &chunk[..chunk.len().min(SCREEN_CARRY_BYTES)];
                let mut window = Vec::with_capacity(self.carry.len() + head.len());
                window.extend_from_slice(&self.carry);
                window.extend_from_slice(head);
                self.eicar_found = super::asset_scan::contains_eicar(&window);
            }
            self.eicar_found |= super::asset_scan::contains_eicar(chunk);
        }
        if chunk.len() >= SCREEN_CARRY_BYTES {
            self.carry.clear();
            self.carry
                .extend_from_slice(&chunk[chunk.len() - SCREEN_CARRY_BYTES..]);
        } else {
            self.carry.extend_from_slice(chunk);
            let overflow = self.carry.len().saturating_sub(SCREEN_CARRY_BYTES);
            if overflow > 0 {
                self.carry.drain(..overflow);
            }
        }
    }

    fn mark_source_failed(&mut self) {
        self.source_failed = true;
    }

    /// The verdict over everything seen so far.
    pub(super) fn verdict(&self) -> StreamedObjectVerdict {
        StreamedObjectVerdict {
            size_bytes: self.bytes_seen,
            sha256: hex_lower(&self.hasher.clone().finalize()),
            eicar_found: self.eicar_found,
            source_failed: self.source_failed,
        }
    }
}

/// What a bounded-memory pass over an object proved about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StreamedObjectVerdict {
    pub(super) size_bytes: u64,
    pub(super) sha256: String,
    /// The offline malware-signature scan, run over every byte (not a sample).
    pub(super) eicar_found: bool,
    /// The source read failed part-way, so `size_bytes`/`sha256` describe only
    /// a prefix of the object and prove nothing about it.
    pub(super) source_failed: bool,
}

impl StreamedObjectVerdict {
    /// Whether the streamed bytes match the registered intent exactly.
    ///
    /// Length AND digest, over a stream that did not fail: a truncated or
    /// substituted object cannot satisfy both, so this is a complete proof
    /// without needing to observe the source's end-of-stream (which the
    /// `Content-Length`-framed destination PUT does not give us).
    pub(super) fn matches(&self, expected_size: u64, expected_sha256: &str) -> bool {
        !self.source_failed && self.size_bytes == expected_size && self.sha256 == expected_sha256
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// A pass-through byte stream that folds every chunk into a shared
/// [`StreamingObjectScreen`] on its way to the destination PUT.
///
/// It is a hand-written `Stream` rather than a `map()` adapter so it can
/// distinguish a source *failure* from a source that simply ran out — the
/// difference between a 503 infrastructure failure and a 422 content
/// rejection.
struct ScreeningStream {
    inner: ObjectByteStream,
    screen: Arc<Mutex<StreamingObjectScreen>>,
}

impl Stream for ScreeningStream {
    type Item = anyhow::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Ok(mut screen) = self.screen.lock() {
                    screen.update(&chunk);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                if let Ok(mut screen) = self.screen.lock() {
                    screen.mark_source_failed();
                }
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The outcome of [`copy_object_with_incremental_screen`].
#[derive(Debug)]
pub(super) enum StreamedCopy {
    /// The source object does not exist (bucket 404).
    SourceMissing,
    /// The copy ran to completion. `verdict` still has to be checked against
    /// the registered intent -- a completed copy is NOT an accepted commit.
    Copied(StreamedObjectVerdict),
    /// The destination PUT failed *and* the gateway's own byte accounting
    /// agrees the payload did not match the registered intent, which is what
    /// an S3-compatible bucket does when the streamed bytes contradict the
    /// signed `x-amz-content-sha256`. Reported as a content rejection because
    /// the gateway corroborated it, not because the bucket said so.
    RejectedByPayloadMismatch(StreamedObjectVerdict),
}

/// Streams `source_key` into `dest_key` in bounded memory, hashing and
/// screening every byte on the way through (issue #259).
///
/// `expected_sha256`/`expected_size` describe the bytes the intent registered;
/// they are what the destination PUT is SigV4-signed against, so a real bucket
/// independently refuses a payload that contradicts them. The returned verdict
/// is the gateway's own, computed from the bytes it actually forwarded — the
/// caller decides admission from that, never from the bucket's acceptance.
pub(super) async fn copy_object_with_incremental_screen(
    bucket: &dyn AssetObjectStore,
    source_key: &str,
    dest_key: &str,
    expected_size: u64,
    expected_sha256: &str,
    content_type: &str,
) -> anyhow::Result<StreamedCopy> {
    let Some(source) = bucket.get_object_stream(source_key).await? else {
        return Ok(StreamedCopy::SourceMissing);
    };
    let screen = Arc::new(Mutex::new(StreamingObjectScreen::new()));
    let body: ObjectByteStream = Box::pin(ScreeningStream {
        inner: source,
        screen: Arc::clone(&screen),
    });
    let put = bucket
        .put_object_stream(dest_key, content_type, expected_size, expected_sha256, body)
        .await;
    let verdict = screen
        .lock()
        .map_err(|_| anyhow::anyhow!("asset stream screening state was poisoned"))?
        .verdict();
    match put {
        Ok(()) => Ok(StreamedCopy::Copied(verdict)),
        Err(error) => {
            // Only claim a content rejection when our own accounting proves it:
            // the source ended cleanly and the bytes disagree with the intent.
            // Anything else is an infrastructure failure and must surface as one.
            if !verdict.source_failed && !verdict.matches(expected_size, expected_sha256) {
                Ok(StreamedCopy::RejectedByPayloadMismatch(verdict))
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[path = "asset_stream_test.rs"]
mod asset_stream_test;
