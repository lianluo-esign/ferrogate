/**
 * `src/inference/estimate.ts` — the PRE-DISPATCH token estimate.
 *
 * Every case here is derived from the Rust it ports (`chat.rs`, `messages.rs`,
 * `embeddings.rs`, `images.rs`); where the Rust tree has a matching `#[test]`
 * the case is named after it and asserts the same numbers.
 *
 * Two groups deserve calling out because they are the reason the estimate is
 * security-relevant rather than cosmetic:
 *
 *  - the pre-tokenized `input` cases on `/v1/embeddings` (issue #207) — a
 *    character-only count reads a token-id array as zero tokens;
 *  - the `n` clamp on `/v1/images/generations` (issue #275).
 *
 * The final group pins the DIRECTION of the `chars/4` approximation against the
 * BPE leg that is not ported (see the module PORT-TODO): the heuristic must
 * never under-count natural-language text relative to a real BPE tokenizer, so
 * the gate fails closed.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_COMPLETION_TOKEN_RESERVATION,
  estimateChatCompletionUsage,
  estimateEmbeddingsUsage,
  estimateImagesUsage,
  estimateMessagesUsage,
  isNonPromptRequestField,
  requestedImageCount,
} from "../../src/inference/estimate.js";
import { MAX_ESTIMATED_IMAGE_COUNT } from "../../src/inference/schemas.js";

describe("estimateChatCompletionUsage", () => {
  // Rust `estimates_prompt_and_requested_completion_tokens`.
  it("multiplies the requested completion tokens by n", () => {
    const usage = estimateChatCompletionUsage(
      {
        model: "fast-chat",
        messages: [{ role: "user", content: "hello world" }],
        max_tokens: 7,
        n: 2,
      },
      "fast-chat",
    );

    expect(usage.completionTokens).toBe(14);
    // "user" (4) + "hello world" (11) = 15 chars → (15+3)/4 = 4, + 1 message × 4.
    expect(usage.promptTokens).toBe(8);
    expect(usage.totalTokens).toBe(usage.promptTokens + usage.completionTokens);
  });

  // Rust `reserves_default_completion_tokens_when_unbounded`.
  it("reserves the 512-token default when the request is unbounded", () => {
    const usage = estimateChatCompletionUsage({ model: "fast-chat", messages: [] }, "fast-chat");

    expect(usage.completionTokens).toBe(DEFAULT_COMPLETION_TOKEN_RESERVATION);
    expect(usage.totalTokens).toBe(DEFAULT_COMPLETION_TOKEN_RESERVATION);
    expect(usage.promptTokens).toBe(0);
  });

  it("prefers max_completion_tokens over max_tokens", () => {
    const usage = estimateChatCompletionUsage(
      { model: "m", messages: [], max_completion_tokens: 9, max_tokens: 1000 },
      "m",
    );
    expect(usage.completionTokens).toBe(9);
  });

  it("excludes the request knobs from the prompt count", () => {
    // Every excluded field carries a long string; if the filter were dropped the
    // prompt estimate would jump by ~ (11 fields × 40 chars) / 4.
    const filler = "x".repeat(40);
    const knobs = {
      model: filler,
      stream: filler,
      max_tokens: filler,
      max_completion_tokens: filler,
      temperature: filler,
      top_p: filler,
      n: filler,
      presence_penalty: filler,
      frequency_penalty: filler,
      seed: filler,
      user: filler,
    };
    const usage = estimateChatCompletionUsage({ ...knobs, messages: [] }, "m");

    expect(usage.promptTokens).toBe(0);
    // Strings are not `as_u64`, so both bounds fall back to the default.
    expect(usage.completionTokens).toBe(DEFAULT_COMPLETION_TOKEN_RESERVATION);
  });

  it("names exactly the Rust non-prompt field set", () => {
    for (const key of [
      "model",
      "stream",
      "max_tokens",
      "max_completion_tokens",
      "temperature",
      "top_p",
      "n",
      "presence_penalty",
      "frequency_penalty",
      "seed",
      "user",
    ]) {
      expect(isNonPromptRequestField(key), key).toBe(true);
    }
    for (const key of ["messages", "tools", "input", "system", "content", "role"]) {
      expect(isNonPromptRequestField(key), key).toBe(false);
    }
  });

  it("charges 4 tokens of ChatML framing per message", () => {
    const one = estimateChatCompletionUsage({ messages: [{ role: "" }] }, "m");
    const three = estimateChatCompletionUsage(
      { messages: [{ role: "" }, { role: "" }, { role: "" }] },
      "m",
    );
    expect(three.promptTokens - one.promptTokens).toBe(8);
  });

  it("counts Unicode SCALAR values, not UTF-16 code units", () => {
    // "😀" is 2 UTF-16 units and 1 Rust `char`. 8 of them are 8 chars → 2
    // tokens (not 16 units → 4), so a JS `.length` count would DOUBLE this.
    const usage = estimateChatCompletionUsage({ messages: [{ content: "😀".repeat(8) }] }, "m");
    expect(usage.promptTokens).toBe(Math.floor((8 + 3) / 4) + 4);
  });

  describe("serde_json as_u64 semantics", () => {
    it("ignores a negative max_tokens and falls back to the default", () => {
      expect(
        estimateChatCompletionUsage({ messages: [], max_tokens: -1 }, "m").completionTokens,
      ).toBe(DEFAULT_COMPLETION_TOKEN_RESERVATION);
    });

    it("ignores a fractional max_tokens", () => {
      expect(
        estimateChatCompletionUsage({ messages: [], max_tokens: 1.5 }, "m").completionTokens,
      ).toBe(DEFAULT_COMPLETION_TOKEN_RESERVATION);
    });

    it("treats n <= 0 and a non-integer n as one choice", () => {
      for (const n of [0, -3, 2.5, "4", null]) {
        expect(
          estimateChatCompletionUsage({ messages: [], max_tokens: 10, n }, "m").completionTokens,
          `n=${String(n)}`,
        ).toBe(10);
      }
    });
  });
});

describe("estimateMessagesUsage", () => {
  it("has no n multiplier — the Anthropic Messages API has none", () => {
    const usage = estimateMessagesUsage(
      { messages: [{ role: "user", content: "hi" }], max_tokens: 11, n: 5 },
      "claude",
    );
    expect(usage.completionTokens).toBe(11);
  });

  it("defaults the completion reservation to 512", () => {
    expect(estimateMessagesUsage({ messages: [] }, "claude").completionTokens).toBe(
      DEFAULT_COMPLETION_TOKEN_RESERVATION,
    );
  });

  it("counts ONLY the messages, never the sibling request fields", () => {
    const withSiblings = estimateMessagesUsage(
      { messages: [{ content: "abcd" }], tools: [{ description: "z".repeat(400) }] },
      "claude",
    );
    const withoutSiblings = estimateMessagesUsage({ messages: [{ content: "abcd" }] }, "claude");
    expect(withSiblings.promptTokens).toBe(withoutSiblings.promptTokens);
  });

  it("drops the `type` content-block discriminator but keeps its text", () => {
    // `messages.rs::prompt_character_count` filters exactly one key: `type`.
    const typed = estimateMessagesUsage(
      { messages: [{ content: [{ type: "text_block_long_name", text: "abcdefgh" }] }] },
      "claude",
    );
    const untyped = estimateMessagesUsage(
      { messages: [{ content: [{ text: "abcdefgh" }] }] },
      "claude",
    );
    expect(typed.promptTokens).toBe(untyped.promptTokens);
    // 8 chars → 2 tokens, + 1 message × 4.
    expect(typed.promptTokens).toBe(6);
  });
});

describe("estimateEmbeddingsUsage", () => {
  it("counts a string input with the chars/4 heuristic", () => {
    // 16 chars → (16+3)/4 = 4.
    expect(estimateEmbeddingsUsage({ input: "abcdefghijklmnop" }, "e").promptTokens).toBe(4);
  });

  it("has no completion side", () => {
    const usage = estimateEmbeddingsUsage({ input: "abcdefghijklmnop" }, "e");
    expect(usage.completionTokens).toBe(0);
    expect(usage.totalTokens).toBe(usage.promptTokens);
  });

  // Issue #207 — the bypass this arm exists to close.
  it("scores a PRE-TOKENIZED id array at one token per id", () => {
    const ids = Array.from({ length: 50 }, (_, i) => i);
    expect(estimateEmbeddingsUsage({ input: ids }, "e").promptTokens).toBe(50);
  });

  it("scores a BATCH of pre-tokenized arrays element-wise", () => {
    expect(
      estimateEmbeddingsUsage(
        {
          input: [
            [1, 2, 3],
            [4, 5],
          ],
        },
        "e",
      ).promptTokens,
    ).toBe(5);
  });

  it("sums a batch of strings ELEMENT-WISE, not over the concatenation", () => {
    // Each element is rounded on its own: 4 chars → (4+3)/4 = 1, twice = 2.
    // Concatenating first would give 8 chars → (8+3)/4 = 2 as well, so a third
    // element is added to separate the two behaviors: 3 × 1 = 3 element-wise,
    // versus 12 chars → 3 concatenated. Use uneven lengths instead.
    expect(estimateEmbeddingsUsage({ input: ["abcd", "efgh"] }, "e").promptTokens).toBe(2);
    // 5 chars → 2, 1 char → 1, summed = 3; the concatenation (6 chars) → 2.
    expect(estimateEmbeddingsUsage({ input: ["abcde", "f"] }, "e").promptTokens).toBe(3);
  });

  it("floors a present, non-empty input to at least one token", () => {
    // A single character is (1+3)/4 = 1 already; a single `null` element counts
    // 0 and is floored to 1 so a non-empty input always engages the gates.
    expect(estimateEmbeddingsUsage({ input: [null] }, "e").promptTokens).toBe(1);
  });

  it("keeps an EXPLICITLY empty input at zero", () => {
    expect(estimateEmbeddingsUsage({ input: "" }, "e").promptTokens).toBe(0);
    expect(estimateEmbeddingsUsage({ input: [] }, "e").promptTokens).toBe(0);
    expect(estimateEmbeddingsUsage({}, "e").promptTokens).toBe(0);
  });
});

describe("estimateImagesUsage", () => {
  it("carries the image count on the COMPLETION dimension", () => {
    const usage = estimateImagesUsage({ prompt: "a cat", n: 3 });
    expect(usage.promptTokens).toBe(0);
    expect(usage.completionTokens).toBe(3);
    expect(usage.totalTokens).toBe(3);
  });

  it("defaults to one image", () => {
    expect(estimateImagesUsage({ prompt: "a cat" }).completionTokens).toBe(1);
  });

  // Issue #275 — a hostile `n` must not pre-charge an unbounded amount.
  it("clamps a hostile n to MAX_ESTIMATED_IMAGE_COUNT", () => {
    expect(requestedImageCount({ n: 1_000_000_000 })).toBe(MAX_ESTIMATED_IMAGE_COUNT);
    expect(estimateImagesUsage({ n: 1_000_000_000 }).completionTokens).toBe(
      MAX_ESTIMATED_IMAGE_COUNT,
    );
  });

  it("treats n <= 0 as the default, never as zero", () => {
    expect(requestedImageCount({ n: 0 })).toBe(1);
    expect(requestedImageCount({ n: -5 })).toBe(1);
  });
});

/**
 * The approximation contract for the unported BPE leg.
 *
 * The Rust test `known_model_prompt_estimate_uses_the_local_tokenizer` asserts
 * `bpe_prompt < heuristic_prompt` for a natural-language prompt. The heuristic
 * is therefore the LOOSER bound on the estimate and the STRICTER one on the
 * gate: charging it refuses at or before the point Rust would.
 *
 * These cases pin that relationship using the published BPE counts for the same
 * text, so landing a real tokenizer later cannot silently move the estimate in
 * the direction that lets more traffic through than Rust allowed.
 */
describe("the chars/4 approximation fails CLOSED against the BPE leg", () => {
  it("over-estimates the Rust test's natural-language prompt", () => {
    const content = "The quick brown fox jumps over the lazy dog.";
    const body = { model: "gpt-4o", messages: [{ role: "user", content }], max_tokens: 16 };

    // `cl100k_base`/`o200k_base` both tokenize this sentence to 10 tokens; the
    // collected prompt text also includes the "user" role string.
    const BPE_PROMPT_TOKENS = 10 + 1;
    const heuristic = estimateChatCompletionUsage(body, "gpt-4o");

    expect(heuristic.promptTokens - 4).toBeGreaterThan(BPE_PROMPT_TOKENS);
  });

  it("keeps the completion side identical either way", () => {
    // Only the PROMPT side would change under a tokenizer; the reservation is
    // read straight off the request, so a BPE leg must not touch it.
    const body = { messages: [{ content: "hello" }], max_tokens: 33, n: 2 };
    expect(estimateChatCompletionUsage(body, "gpt-4o").completionTokens).toBe(66);
    expect(estimateChatCompletionUsage(body, "opaque-tenant-alias").completionTokens).toBe(66);
  });
});
