//! Local BPE tokenizer for accurate PRE-request token estimation (issue #282).
//!
//! Before a request is dispatched the gateway estimates its token usage to size
//! the TPM/budget quota pre-check, the prepaid-wallet reservation, and the
//! lowest-cost route ranking (`route_estimated_cost`). Historically that
//! estimate was a coarse `chars / 4` heuristic. This module replaces the
//! PROMPT-side estimate with a real BPE token count for model families whose
//! tokenizer we can run locally and offline, falling back to the heuristic for
//! everything else.
//!
//! Post-request reconciliation is intentionally untouched: the provider's
//! reported usage stays authoritative at settlement. The local tokenizer only
//! sharpens the pre-dispatch reservation so it over/under-reserves less.
//!
//! The vocabularies (`cl100k_base`, `o200k_base`) are embedded in `tiktoken-rs`
//! and materialized lazily through its `*_singleton()` accessors; there is no
//! network access at build or run time.

use tiktoken_rs::{cl100k_base_singleton, o200k_base_singleton, CoreBPE};

/// A BPE encoding we can evaluate locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// OpenAI `o200k_base` — GPT-4o / GPT-4.1 / o-series reasoning models.
    O200kBase,
    /// OpenAI `cl100k_base` — GPT-4 / GPT-3.5 / `text-embedding-3*`. Also used
    /// as a close proxy for Anthropic Claude text: Claude's tokenizer is not
    /// published, and `cl100k_base` tracks it far more accurately than `chars/4`
    /// for pre-request sizing (settlement still uses provider-reported usage).
    Cl100kBase,
}

impl Encoding {
    fn bpe(self) -> &'static CoreBPE {
        match self {
            Encoding::O200kBase => o200k_base_singleton(),
            Encoding::Cl100kBase => cl100k_base_singleton(),
        }
    }

    /// Ordinary (no special tokens) BPE token count for `text`.
    pub(crate) fn count(self, text: &str) -> u64 {
        self.bpe().count_ordinary(text) as u64
    }
}

/// Select the local encoding for a model name, or `None` when no local
/// tokenizer applies (the caller then falls back to the `chars/4` heuristic).
///
/// Matching is a prefix/substring check over the lowercased name so it works
/// on both provider model ids (`gpt-4o-mini`) and logical aliases that embed a
/// known family (`gpt-4o-fast`). An alias that names no known family — the
/// common case for opaque tenant aliases — resolves to `None` by design.
pub(crate) fn encoding_for_model(model: &str) -> Option<Encoding> {
    let model = model.to_ascii_lowercase();

    // OpenAI o200k_base family: GPT-4o, GPT-4.1, ChatGPT-4o, and the o1/o3/o4
    // reasoning series. Checked before the broader `gpt-4` cl100k prefix.
    if model.starts_with("gpt-4o")
        || model.starts_with("gpt-4.1")
        || model.starts_with("chatgpt-4o")
        || model.starts_with("o1")
        || model.starts_with("o3")
        || model.starts_with("o4")
    {
        return Some(Encoding::O200kBase);
    }

    // OpenAI cl100k_base family: GPT-4 (non-o), GPT-3.5, and the v3 / ada-002
    // embedding models.
    if model.starts_with("gpt-4")
        || model.starts_with("gpt-3.5")
        || model.starts_with("text-embedding-3")
        || model.starts_with("text-embedding-ada")
    {
        return Some(Encoding::Cl100kBase);
    }

    // Anthropic Claude: no public BPE — approximate with cl100k_base.
    if model.contains("claude") {
        return Some(Encoding::Cl100kBase);
    }

    None
}

/// Count tokens for `text` under the encoding chosen for `model`, or `None`
/// when no local tokenizer applies (caller falls back to the heuristic).
pub(crate) fn count_tokens(model: &str, text: &str) -> Option<u64> {
    encoding_for_model(model).map(|encoding| encoding.count(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A local BPE count matches the known tiktoken reference for a sample
    // string, per encoding. These reference lengths are the exact
    // `encode_ordinary(...).len()` OpenAI's tiktoken produces for the string.
    #[test]
    fn cl100k_count_matches_the_known_reference() {
        // "tiktoken is great!" -> [83, 1609, 5963, 374, 2294, 0] under cl100k.
        assert_eq!(Encoding::Cl100kBase.count("tiktoken is great!"), 6);
    }

    #[test]
    fn o200k_count_matches_the_known_reference() {
        // Same sample string under o200k_base -> 6 tokens.
        assert_eq!(Encoding::O200kBase.count("tiktoken is great!"), 6);
    }

    // The two encodings genuinely diverge on some inputs (proving per-encoding
    // selection is load-bearing, not cosmetic). "안녕하세요 세계" (Korean)
    // tokenizes to more tokens under cl100k_base than under o200k_base, whose
    // larger multilingual vocab packs the same bytes more tightly.
    #[test]
    fn encodings_can_diverge() {
        let text = "안녕하세요 세계";
        assert!(
            Encoding::O200kBase.count(text) < Encoding::Cl100kBase.count(text),
            "o200k {} should be tighter than cl100k {}",
            Encoding::O200kBase.count(text),
            Encoding::Cl100kBase.count(text),
        );
    }

    #[test]
    fn per_model_selection_picks_the_right_encoding() {
        assert_eq!(encoding_for_model("gpt-4o"), Some(Encoding::O200kBase));
        assert_eq!(encoding_for_model("gpt-4o-mini"), Some(Encoding::O200kBase));
        assert_eq!(encoding_for_model("gpt-4.1"), Some(Encoding::O200kBase));
        assert_eq!(encoding_for_model("o3-mini"), Some(Encoding::O200kBase));
        assert_eq!(
            encoding_for_model("gpt-4-turbo"),
            Some(Encoding::Cl100kBase)
        );
        assert_eq!(
            encoding_for_model("gpt-3.5-turbo"),
            Some(Encoding::Cl100kBase)
        );
        assert_eq!(
            encoding_for_model("text-embedding-3-small"),
            Some(Encoding::Cl100kBase)
        );
        // Anthropic Claude is proxied through cl100k_base.
        assert_eq!(
            encoding_for_model("claude-3-5-sonnet-20241022"),
            Some(Encoding::Cl100kBase)
        );
        // Case-insensitive.
        assert_eq!(encoding_for_model("GPT-4o"), Some(Encoding::O200kBase));
    }

    #[test]
    fn unknown_model_has_no_local_encoding() {
        assert_eq!(encoding_for_model("fast-chat"), None);
        assert_eq!(encoding_for_model("mistral-large"), None);
        assert_eq!(count_tokens("fast-chat", "hello world"), None);
    }

    #[test]
    fn count_tokens_uses_the_selected_encoding() {
        assert_eq!(count_tokens("gpt-4o", "tiktoken is great!"), Some(6));
        assert_eq!(count_tokens("gpt-4-turbo", "tiktoken is great!"), Some(6));
    }

    // The BPE count is materially more accurate than chars/4 for natural text:
    // for a plain English sentence the tokenizer lands well under the chars/4
    // upper bound, which is exactly the over-reservation #282 set out to shrink.
    #[test]
    fn bpe_count_is_tighter_than_the_char_heuristic() {
        let text = "The quick brown fox jumps over the lazy dog.";
        let heuristic = (text.chars().count() as u64).div_ceil(4);
        let bpe = count_tokens("gpt-4o", text).expect("gpt-4o has a local encoding");
        assert!(
            bpe < heuristic,
            "bpe {bpe} should be tighter than heuristic {heuristic}"
        );
    }
}
