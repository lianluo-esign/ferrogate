// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit tests for the in-process semantic response cache (#273):
// cosine similarity, feature-hashing embedder behavior, threshold-gated
// lookup, per-scope isolation, TTL expiry, and record-cap eviction.

use super::*;

fn response(marker: &str) -> AiCachedResponse {
    AiCachedResponse {
        status_code: 200,
        content_type: "application/json".to_string(),
        body: marker.as_bytes().to_vec(),
    }
}

#[test]
fn cosine_similarity_of_identical_vectors_is_one() {
    let vector = embed_text("the quick brown fox jumps over the lazy dog");
    let similarity = cosine_similarity(&vector, &vector);
    assert!(
        (similarity - 1.0).abs() < 1e-4,
        "similarity was {similarity}"
    );
}

#[test]
fn cosine_similarity_is_zero_for_length_mismatch() {
    assert_eq!(cosine_similarity(&[1.0, 0.0], &[1.0]), 0.0);
}

#[test]
fn cosine_similarity_is_zero_for_zero_vector() {
    let zero = vec![0.0f32; SEMANTIC_EMBED_DIMS];
    let other = embed_text("hello world");
    assert_eq!(cosine_similarity(&zero, &other), 0.0);
}

#[test]
fn near_duplicate_prompts_are_similar_and_disjoint_are_not() {
    let base = embed_text("Please summarize the quarterly earnings report for Acme Corp");
    let paraphrase =
        embed_text("Please summarize the quarterly earnings report for Acme Corp today");
    let unrelated = embed_text("Translate this recipe for banana bread into French");

    let near = cosine_similarity(&base, &paraphrase);
    let far = cosine_similarity(&base, &unrelated);
    assert!(near > 0.9, "near-duplicate similarity too low: {near}");
    assert!(far < 0.5, "unrelated similarity too high: {far}");
    assert!(near > far);
}

#[test]
fn lookup_returns_best_match_above_threshold() {
    let mut cache = SemanticResponseCache::default();
    let scope = 7;
    let stored = embed_text("Please summarize the quarterly earnings report for Acme Corp");
    cache.insert(scope, stored, response("cached"), 300, 100, 1_000);

    let query = embed_text("Please summarize the quarterly earnings report for Acme Corp today");
    let hit = cache.lookup(scope, &query, 0.9, 1_100);
    let (found, similarity) = hit.expect("near-duplicate should hit above threshold");
    assert_eq!(found.body, b"cached");
    assert!(similarity >= 0.9);
}

#[test]
fn lookup_misses_below_threshold() {
    let mut cache = SemanticResponseCache::default();
    let scope = 7;
    cache.insert(
        scope,
        embed_text("Summarize the quarterly earnings report for Acme Corp"),
        response("cached"),
        300,
        100,
        1_000,
    );

    let query = embed_text("Translate this recipe for banana bread into French");
    assert!(cache.lookup(scope, &query, 0.9, 1_100).is_none());
}

#[test]
fn lookup_is_isolated_by_scope() {
    let mut cache = SemanticResponseCache::default();
    let prompt = embed_text("Summarize the quarterly earnings report for Acme Corp");
    cache.insert(1, prompt.clone(), response("tenant-a"), 300, 100, 1_000);

    // Same embedding, different scope bucket (e.g. a different tenant): miss.
    assert!(cache.lookup(2, &prompt, 0.5, 1_100).is_none());
    let (found, _) = cache
        .lookup(1, &prompt, 0.5, 1_100)
        .expect("same scope hits");
    assert_eq!(found.body, b"tenant-a");
}

#[test]
fn expired_entries_are_not_served() {
    let mut cache = SemanticResponseCache::default();
    let prompt = embed_text("Summarize the quarterly earnings report");
    cache.insert(1, prompt.clone(), response("cached"), 60, 100, 1_000);
    // now = 1_000 + 60 = 1_060 is exactly at expiry (expires_at <= now => gone).
    assert!(cache.lookup(1, &prompt, 0.5, 1_060).is_none());
    // Just before expiry it is still served.
    assert!(cache.lookup(1, &prompt, 0.5, 1_059).is_some());
}

#[test]
fn eviction_respects_the_record_cap() {
    let mut cache = SemanticResponseCache::default();
    let max_records = 2;
    for index in 0..5 {
        let prompt = embed_text(&format!("distinct prompt number {index}"));
        cache.insert(
            index,
            prompt,
            response(&index.to_string()),
            300,
            max_records,
            1_000,
        );
    }
    // Oldest three scopes evicted; only the last two survive.
    for index in 0..3 {
        let prompt = embed_text(&format!("distinct prompt number {index}"));
        assert!(cache.lookup(index, &prompt, 0.5, 1_000).is_none());
    }
    for index in 3..5 {
        let prompt = embed_text(&format!("distinct prompt number {index}"));
        assert!(cache.lookup(index, &prompt, 0.5, 1_000).is_some());
    }
}

#[test]
fn prompt_text_extracts_from_chat_messages() {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What is the capital of France?"},
        ],
    });
    let text = prompt_text_for_embedding(&body);
    assert!(text.contains("You are helpful."));
    assert!(text.contains("capital of France"));
}

#[test]
fn prompt_text_handles_content_part_arrays() {
    let body = serde_json::json!({
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "describe this"},
                {"type": "image_url", "image_url": {"url": "http://example/x.png"}},
            ]},
        ],
    });
    let text = prompt_text_for_embedding(&body);
    assert!(text.contains("describe this"));
}

#[test]
fn prompt_text_falls_back_to_full_body() {
    let body = serde_json::json!({"unexpected": "shape"});
    let text = prompt_text_for_embedding(&body);
    assert!(text.contains("unexpected"));
}
