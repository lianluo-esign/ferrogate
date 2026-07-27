// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: In-process semantic AI response cache (issue #273). Sits BEHIND
// the same cache seam as the exact-match cache: on an exact-match miss the
// gateway embeds the request prompt and serves a prior cached response whose
// stored embedding is within a configured cosine-similarity threshold. Entries
// are bucketed by a *scope key* — a fingerprint of route, tenant, logical and
// provider model, provider, and the guardrail-policy fingerprint — so tenant
// isolation and guardrail-policy invalidation carry over from the exact key
// (no cross-tenant bleed; a tightened policy immediately misses old entries).
// In-tree cosine similarity over stored f32 vectors; no external vector DB.

use std::collections::HashMap;
use std::collections::VecDeque;

use super::fnv1a64;
use super::AiCachedResponse;

/// Dimensionality of the local feature-hashing embedder. Fixed so every stored
/// vector is directly comparable under cosine similarity.
pub(crate) const SEMANTIC_EMBED_DIMS: usize = 256;

/// Per-request context threaded through the cache seam when semantic mode is
/// active: the tenant/policy scope bucket and the request-prompt embedding.
#[derive(Debug, Clone)]
pub(crate) struct SemanticCacheContext {
    pub(crate) scope: u64,
    pub(crate) embedding: Vec<f32>,
}

#[derive(Debug, Clone)]
struct SemanticCacheEntry {
    /// Monotonic insertion sequence, used for global FIFO eviction.
    seq: u64,
    embedding: Vec<f32>,
    response: AiCachedResponse,
    expires_at_unix: u64,
}

/// In-process semantic response cache. Buckets entries by scope hash; within a
/// bucket, lookup returns the highest-cosine entry at or above the threshold.
#[derive(Debug, Default)]
pub(crate) struct SemanticResponseCache {
    scopes: HashMap<u64, Vec<SemanticCacheEntry>>,
    /// (scope, seq) in insertion order, for a global cap independent of scope.
    order: VecDeque<(u64, u64)>,
    seq_counter: u64,
    total: usize,
}

impl SemanticResponseCache {
    /// Highest-similarity live entry in `scope` whose cosine similarity to
    /// `embedding` is at or above `threshold`. Expired entries are skipped
    /// (they are reclaimed lazily by the insertion cap, never served). Returns
    /// the response and the observed similarity.
    pub(crate) fn lookup(
        &self,
        scope: u64,
        embedding: &[f32],
        threshold: f32,
        now_unix: u64,
    ) -> Option<(AiCachedResponse, f32)> {
        let entries = self.scopes.get(&scope)?;
        let mut best: Option<(&AiCachedResponse, f32)> = None;
        for entry in entries {
            if entry.expires_at_unix <= now_unix {
                continue;
            }
            let similarity = cosine_similarity(embedding, &entry.embedding);
            if similarity >= threshold && best.is_none_or(|(_, best_sim)| similarity > best_sim) {
                best = Some((&entry.response, similarity));
            }
        }
        best.map(|(response, similarity)| (response.clone(), similarity))
    }

    /// Insert a scoped embedding→response entry, applying the same TTL and
    /// global record cap as the exact-match cache.
    pub(crate) fn insert(
        &mut self,
        scope: u64,
        embedding: Vec<f32>,
        response: AiCachedResponse,
        ttl_secs: u64,
        max_records: usize,
        now_unix: u64,
    ) {
        self.seq_counter = self.seq_counter.saturating_add(1);
        let seq = self.seq_counter;
        self.scopes
            .entry(scope)
            .or_default()
            .push(SemanticCacheEntry {
                seq,
                embedding,
                response,
                expires_at_unix: now_unix.saturating_add(ttl_secs),
            });
        self.order.push_back((scope, seq));
        self.total = self.total.saturating_add(1);
        self.evict_to_cap(max_records);
    }

    fn evict_to_cap(&mut self, max_records: usize) {
        while self.total > max_records {
            let Some((scope, seq)) = self.order.pop_front() else {
                break;
            };
            if let Some(entries) = self.scopes.get_mut(&scope) {
                if let Some(position) = entries.iter().position(|entry| entry.seq == seq) {
                    entries.remove(position);
                    self.total = self.total.saturating_sub(1);
                    if entries.is_empty() {
                        self.scopes.remove(&scope);
                    }
                }
                // A missing seq means the entry was already evicted; the stale
                // order slot is simply dropped without touching `total`.
            }
        }
    }
}

/// Cosine similarity of two equal-length vectors. Returns 0.0 for
/// length-mismatched or zero-magnitude inputs (fail-safe: never a false hit).
pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (left, right) in a.iter().zip(b.iter()) {
        dot += left * right;
        norm_a += left * left;
        norm_b += right * right;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Deterministic, network-free feature-hashing embedder. Tokens are lowercased,
/// hashed into a fixed-dimension signed bag-of-words vector, then L2-normalized.
/// Prompts that share most of their vocabulary (paraphrases, added whitespace,
/// re-ordered clauses) land close in cosine space; disjoint prompts land far
/// apart. This keeps the semantic layer fully in-tree and deterministically
/// testable; a configured embedding model can be substituted here later without
/// touching the cache seam.
pub(crate) fn embed_text(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0f32; SEMANTIC_EMBED_DIMS];
    for token in text
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        let lowered = token.to_ascii_lowercase();
        let hash = fnv1a64(lowered.as_bytes());
        let index = (hash % SEMANTIC_EMBED_DIMS as u64) as usize;
        // Signed hashing (top bit picks the sign) cancels some collisions
        // rather than always accumulating them constructively.
        let sign = if (hash >> 63) & 1 == 1 { -1.0 } else { 1.0 };
        vector[index] += sign;
    }
    let norm: f32 = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value /= norm;
        }
    }
    vector
}

/// Extract the natural-language prompt text an embedding should be computed
/// over from a request body. Handles OpenAI-style `messages[].content` (string
/// or content-part arrays), the Responses `input` field, and a bare `prompt`;
/// falls back to the whole serialized body so an embedding is always produced.
pub(crate) fn prompt_text_for_embedding(body: &serde_json::Value) -> String {
    let mut collected = String::new();

    if let Some(messages) = body.get("messages").and_then(|value| value.as_array()) {
        for message in messages {
            append_content_text(message.get("content"), &mut collected);
        }
    }

    if collected.trim().is_empty() {
        if let Some(input) = body.get("input") {
            append_content_text(Some(input), &mut collected);
        }
    }

    if collected.trim().is_empty() {
        if let Some(prompt) = body.get("prompt").and_then(|value| value.as_str()) {
            collected.push_str(prompt);
        }
    }

    if collected.trim().is_empty() {
        return body.to_string();
    }
    collected
}

fn append_content_text(content: Option<&serde_json::Value>, out: &mut String) {
    match content {
        Some(serde_json::Value::String(text)) => {
            push_with_separator(out, text);
        }
        Some(serde_json::Value::Array(parts)) => {
            for part in parts {
                if let Some(text) = part.get("text").and_then(|value| value.as_str()) {
                    push_with_separator(out, text);
                } else if let Some(text) = part.as_str() {
                    push_with_separator(out, text);
                }
            }
        }
        _ => {}
    }
}

fn push_with_separator(out: &mut String, text: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}

#[cfg(test)]
#[path = "semantic_cache_test.rs"]
mod semantic_cache_test;
