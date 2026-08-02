/**
 * PINS FOR THE THREE DELIBERATE NON-PARITIES in `src/streaming/`.
 *
 * Each of these is a PORT-TODO that is deliberately NOT closed, because closing
 * it would add behavior the Rust tree does not have. That makes them the most
 * fragile kind of comment: a later reader sees a "missing" feature, adds it,
 * and the port silently diverges from the thing it is a port of.
 *
 * So each one is asserted here in its CURRENT, Rust-matching form. If someone
 * implements the "obvious fix", the corresponding test goes red and they are
 * forced to raise it as a behavior change — which is exactly the conversation
 * that should happen — rather than discovering it in production.
 *
 * None of these is a platform limit. All three are parity decisions.
 */
import { describe, expect, test } from "vitest";
import { defaultStreamNormalizers } from "../../src/inference/index.js";
import { OPENAI_REVERSE_NORMALIZER_UNPORTED } from "../../src/streaming/openai.js";
import { responsesNormalizeStream } from "../../src/streaming/responses.js";
import { extractUsage } from "../../src/streaming/usage.js";
import { bytes, drainText, jsonEvents, streamOf } from "./helpers.js";

// ---------------------------------------------------------------------------
// 1. No Anthropic-events → OpenAI-chunks reverse normalizer
// ---------------------------------------------------------------------------

describe("there is no Anthropic → OpenAI reverse stream normalizer", () => {
  test("an Anthropic upstream on the OpenAI chat ingress is relayed UNCHANGED", () => {
    // The Rust tower has three normalizers and none of them runs in this
    // direction: OpenAI → Anthropic (`MessagesStreamNormalizer`),
    // OpenAI/Anthropic/Gemini → Responses (`ResponsesStreamNormalizer`), and
    // Anthropic-object → Anthropic-SSE (`message_to_anthropic_sse`). An
    // Anthropic upstream answering `/v1/chat/completions` therefore streams
    // Anthropic frames to an OpenAI client, on purpose.
    const normalizer = defaultStreamNormalizers.normalizerFor({
      dialect: "openai.chat",
      providerKind: "anthropic",
      logicalModel: "claude-logical",
      requestId: "fg-test",
      contentType: "text/event-stream",
    });

    expect(normalizer).toBeNull();
    expect(OPENAI_REVERSE_NORMALIZER_UNPORTED).toBe(true);
  });

  test("and the two directions that DO exist still normalize", () => {
    // The negative above must not be satisfiable by a normalizer registry that
    // returns `null` for everything.
    expect(
      defaultStreamNormalizers.normalizerFor({
        dialect: "anthropic.messages",
        providerKind: "openai",
        logicalModel: "gpt-4o-mini",
        requestId: "fg-test",
        contentType: "text/event-stream",
      }),
    ).not.toBeNull();
    expect(
      defaultStreamNormalizers.normalizerFor({
        dialect: "openai.responses",
        providerKind: "anthropic",
        logicalModel: "claude-logical",
        requestId: "fg-test",
        contentType: "text/event-stream",
      }),
    ).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. The Anthropic `delta.text` double-emission on the Responses normalizer
// ---------------------------------------------------------------------------

describe("an Anthropic text delta is emitted TWICE on the Responses ingress", () => {
  test("as output_text.delta AND as function_call_arguments.delta", async () => {
    // `extract_function_call_deltas` reads the tool-argument fragment from
    // `delta.text` for `kind: "anthropic"` — the same field a plain text delta
    // uses — so a text-only Anthropic stream produces both events. This is
    // observable behavior a client may already depend on; narrowing it to
    // `delta.partial_json` is a behavior change, not a port fix.
    const sse = await drainText(
      streamOf([
        bytes(
          'event: content_block_delta\ndata: {"index":0,"delta":{"type":"text_delta","text":"hello"}}\n\n',
        ),
        bytes("data: [DONE]\n\n"),
      ]).pipeThrough(
        responsesNormalizeStream({
          providerKind: "anthropic",
          requestId: "fg-test",
          contentType: "text/event-stream",
        }),
      ),
    );

    const textDeltas = jsonEvents(sse, "response.output_text.delta") as { delta: string }[];
    expect(textDeltas.map((event) => event.delta)).toContain("hello");

    const argumentDeltas = jsonEvents(sse, "response.function_call_arguments.delta") as {
      delta: string;
    }[];
    expect(argumentDeltas.map((event) => event.delta)).toContain("hello");
  });

  test("an OpenAI upstream does NOT double-emit — the quirk is Anthropic-only", async () => {
    const sse = await drainText(
      streamOf([
        bytes('data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'),
        bytes("data: [DONE]\n\n"),
      ]).pipeThrough(
        responsesNormalizeStream({
          providerKind: "openai_compatible",
          requestId: "fg-test",
          contentType: "text/event-stream",
        }),
      ),
    );

    expect((jsonEvents(sse, "response.output_text.delta") as unknown[]).length).toBeGreaterThan(0);
    expect(jsonEvents(sse, "response.function_call_arguments.delta")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. Anthropic prompt-cache counters are not metered
// ---------------------------------------------------------------------------

describe("Anthropic cache_* token counters are deliberately not read", () => {
  test("input_tokens alone is the prompt count, cache counters are ignored", () => {
    // `ferrogate-providers/src/anthropic.rs::extract_usage` reads exactly
    // `input_tokens` / `output_tokens`. Folding the cache counters in would
    // change what the gateway BILLS, which is a metering decision that belongs
    // with `@ferrogate/providers`, not a normalization gap to be patched here.
    const usage = extractUsage(
      {
        message: {
          usage: {
            input_tokens: 11,
            output_tokens: 0,
            cache_creation_input_tokens: 900,
            cache_read_input_tokens: 4000,
          },
        },
      },
      "anthropic",
    );

    expect(usage?.promptTokens).toBe(11);
    // Not 11 + 900 + 4000, and not 11 + 900.
    expect(usage?.promptTokens).not.toBe(4911);
  });

  test("a payload carrying ONLY cache counters reports no usage at all", () => {
    // The `None`-unless-a-known-counter-is-present rule: a cache-only frame
    // must not clobber an earlier real reading with a synthesized one.
    expect(
      extractUsage(
        { usage: { cache_creation_input_tokens: 900, cache_read_input_tokens: 4000 } },
        "anthropic",
      ),
    ).toBeUndefined();
  });
});
