/**
 * INCREMENTAL streaming output screening.
 *
 * The two properties that matter:
 *  1. the stream is NOT buffered — frames that clear the policy reach the
 *     client before the stream ends;
 *  2. a frame that trips the policy is NEVER forwarded, and the block is
 *     delivered in band in the dialect the client was promised.
 */
import { describe, expect, test } from "vitest";
import {
  GuardrailEngine,
  InMemoryGuardrailEvidenceSink,
  type StreamScreenOutcome,
  screenSseBody,
} from "../../src/guardrails/index.js";
import { byteStreamFrom, parseSse, readAllText } from "../../src/streaming/sse.js";
import { PROBE_SECRET, chatContext, secretScanPolicy, sourceFor } from "./fixtures.js";

function chatFrame(content: string): string {
  return `data: ${JSON.stringify({
    id: "chatcmpl-1",
    object: "chat.completion.chunk",
    choices: [{ index: 0, delta: { content } }],
  })}\n\n`;
}

const RESPONSE_BLOCK_POLICY = secretScanPolicy({
  policyId: "stream-block",
  stage: "response",
  streaming: "buffer_and_enforce",
});

const RESPONSE_REDACT_POLICY = secretScanPolicy({
  policyId: "stream-redact",
  stage: "response",
  streaming: "buffer_and_enforce",
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "redacted" }],
});

function screen(
  chunks: readonly string[],
  policy = RESPONSE_BLOCK_POLICY,
  dialect: "openai.chat" | "openai.responses" | "anthropic.messages" = "openai.chat",
): { text: Promise<string>; outcome: () => StreamScreenOutcome | undefined } {
  let outcome: StreamScreenOutcome | undefined;
  const engine = new GuardrailEngine({
    policies: sourceFor(policy),
    evidence: new InMemoryGuardrailEvidenceSink(),
  });
  const stream = screenSseBody(byteStreamFrom([...chunks]), {
    engine,
    context: chatContext({
      streaming: true,
      envelope: { protocol: "chat_completions", stage: "response", segments: [] },
    }),
    dialect,
    protocol: "chat_completions",
    requestId: "fg-0000000000000001",
    onOutcome: (value) => {
      outcome = value;
    },
  });
  return { text: readAllText(stream), outcome: () => outcome };
}

describe("incremental screening", () => {
  test("a clean stream passes through frame for frame", async () => {
    const { text, outcome } = screen([chatFrame("Hello"), chatFrame(" world"), "data: [DONE]\n\n"]);
    const out = await text;
    expect(out).toContain("Hello");
    expect(out).toContain(" world");
    expect(out).toContain("[DONE]");
    expect(outcome()).toEqual({ kind: "clean" });
  });

  test("the stream is NOT buffered: cleared frames are emitted before EOF", async () => {
    // A never-ending source: if the screener buffered, `read()` would hang.
    const encoder = new TextEncoder();
    let released = false;
    const source = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!released) {
          released = true;
          controller.enqueue(encoder.encode(chatFrame("first token")));
        }
        // deliberately never closes
      },
    });
    const engine = new GuardrailEngine({
      policies: sourceFor(RESPONSE_BLOCK_POLICY),
      evidence: new InMemoryGuardrailEvidenceSink(),
    });
    const reader = screenSseBody(source, {
      engine,
      context: chatContext({
        streaming: true,
        envelope: { protocol: "chat_completions", stage: "response", segments: [] },
      }),
      dialect: "openai.chat",
      protocol: "chat_completions",
      requestId: "fg-0000000000000001",
    }).getReader();
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toContain("first token");
    await reader.cancel();
  });

  test("a secret mid-stream blocks: the offending frame is never forwarded", async () => {
    const { text, outcome } = screen([
      chatFrame("here is the key: "),
      chatFrame(PROBE_SECRET),
      chatFrame(" keep it safe"),
      "data: [DONE]\n\n",
    ]);
    const out = await text;

    expect(out).toContain("here is the key: ");
    // The frame carrying the secret is dropped entirely.
    expect(out).not.toContain(PROBE_SECRET);
    // ...and everything after it too.
    expect(out).not.toContain("keep it safe");

    const settled = outcome();
    expect(settled?.kind).toBe("blocked");
    if (settled?.kind === "blocked") {
      expect(settled.match.code).toBe("guardrail_blocked");
      expect(settled.frameIndex).toBe(1);
    }
  });

  test("the openai.chat block frame carries the FerroGate error envelope", async () => {
    const { text } = screen([chatFrame(PROBE_SECRET), "data: [DONE]\n\n"]);
    const frames = parseSse(await text);
    const error = JSON.parse(frames[0]?.data ?? "{}");
    expect(error).toEqual({
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
        request_id: "fg-0000000000000001",
      },
    });
    expect(frames[1]?.data).toBe("[DONE]");
  });

  test("the anthropic.messages block frame uses the Rust error_sse shape", async () => {
    const frame = `event: content_block_delta\ndata: ${JSON.stringify({
      type: "content_block_delta",
      index: 0,
      delta: { type: "text_delta", text: PROBE_SECRET },
    })}\n\n`;
    const { text } = screen([frame], RESPONSE_BLOCK_POLICY, "anthropic.messages");
    const frames = parseSse(await text);
    expect(frames[0]?.event).toBe("error");
    expect(JSON.parse(frames[0]?.data ?? "{}")).toEqual({
      type: "error",
      error: { type: "guardrail_blocked", message: "request blocked by guardrail policy" },
    });
  });

  test("the openai.responses block frame uses the response.failed shape", async () => {
    const frame = `event: response.output_text.delta\ndata: ${JSON.stringify({
      type: "response.output_text.delta",
      delta: PROBE_SECRET,
    })}\n\n`;
    const { text } = screen([frame], RESPONSE_BLOCK_POLICY, "openai.responses");
    const frames = parseSse(await text);
    expect(frames[0]?.event).toBe("response.failed");
    expect(JSON.parse(frames[0]?.data ?? "{}")).toEqual({
      request_id: "fg-0000000000000001",
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
      },
    });
    expect(frames[1]?.data).toBe("[DONE]");
  });
});

/** A native Gemini `streamGenerateContent?alt=sse` frame. */
function geminiFrame(text: string): string {
  return `data: ${JSON.stringify({
    candidates: [{ content: { role: "model", parts: [{ text }] } }],
  })}\n\n`;
}

/** Screen a native Gemini SSE stream — the `"gemini"` dialect + protocol. */
function screenGemini(chunks: readonly string[]): {
  text: Promise<string>;
  outcome: () => StreamScreenOutcome | undefined;
} {
  let outcome: StreamScreenOutcome | undefined;
  const engine = new GuardrailEngine({
    policies: sourceFor(RESPONSE_BLOCK_POLICY),
    evidence: new InMemoryGuardrailEvidenceSink(),
  });
  const stream = screenSseBody(byteStreamFrom([...chunks]), {
    engine,
    context: chatContext({
      streaming: true,
      envelope: { protocol: "gemini", stage: "response", segments: [] },
    }),
    dialect: "gemini",
    protocol: "gemini",
    requestId: "fg-0000000000000001",
    onOutcome: (value) => {
      outcome = value;
    },
  });
  return { text: readAllText(stream), outcome: () => outcome };
}

describe("gemini native streaming is screened", () => {
  test("a clean gemini stream passes through frame for frame", async () => {
    const { text, outcome } = screenGemini([geminiFrame("Hello"), geminiFrame(" world")]);
    const out = await text;
    expect(out).toContain("Hello");
    expect(out).toContain(" world");
    expect(outcome()).toEqual({ kind: "clean" });
  });

  test("a secret in candidates[].content.parts[].text blocks the stream", async () => {
    const { text, outcome } = screenGemini([
      geminiFrame("here is the key: "),
      geminiFrame(PROBE_SECRET),
      geminiFrame(" keep it safe"),
    ]);
    const out = await text;
    expect(out).toContain("here is the key: ");
    // The offending frame — and everything after it — is never forwarded.
    expect(out).not.toContain(PROBE_SECRET);
    expect(out).not.toContain("keep it safe");

    const settled = outcome();
    expect(settled?.kind).toBe("blocked");
    if (settled?.kind === "blocked") {
      expect(settled.match.code).toBe("guardrail_blocked");
      expect(settled.frameIndex).toBe(1);
    }
  });

  test("the gemini block frame is the FerroGate error as an unnamed data event, with NO [DONE]", async () => {
    const { text } = screenGemini([geminiFrame(PROBE_SECRET)]);
    const frames = parseSse(await text);
    // Exactly one frame: the synthesized error. Gemini's SSE transport has no
    // `[DONE]` sentinel, so none is fabricated.
    expect(frames).toHaveLength(1);
    expect(frames[0]?.event).toBeUndefined();
    expect(JSON.parse(frames[0]?.data ?? "{}")).toEqual({
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
        request_id: "fg-0000000000000001",
      },
    });
    expect(frames.some((f) => f.data === "[DONE]")).toBe(false);
  });
});

describe("a marker split across frames", () => {
  test("a secret straddling two frames is still caught", async () => {
    const half = Math.floor(PROBE_SECRET.length / 2);
    const { text, outcome } = screen([
      chatFrame(PROBE_SECRET.slice(0, half)),
      chatFrame(PROBE_SECRET.slice(half)),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(outcome()?.kind).toBe("blocked");
    // The completing half never ships.
    expect(out).not.toContain(PROBE_SECRET.slice(half));
    expect(out).not.toContain(PROBE_SECRET);
  });

  test("a secret split across a mid-UTF-8 CHUNK boundary is caught", async () => {
    // Chunk boundaries are not frame boundaries. Split the WIRE BYTES in the
    // middle of a multi-byte character and in the middle of the frame — the
    // classic streaming bug a normalizer that only works on clean boundaries
    // hides.
    const frame = chatFrame(`héllo ${PROBE_SECRET} ✓`);
    const bytes = new TextEncoder().encode(frame);
    // Find a byte offset that lands INSIDE the 2-byte U+00E9 sequence.
    const eIndex = bytes.indexOf(0xc3);
    expect(eIndex).toBeGreaterThan(0);
    expect(bytes[eIndex + 1]).toBe(0xa9);
    const chunks = [bytes.slice(0, eIndex + 1), bytes.slice(eIndex + 1)];

    let outcome: StreamScreenOutcome | undefined;
    const engine = new GuardrailEngine({
      policies: sourceFor(RESPONSE_BLOCK_POLICY),
      evidence: new InMemoryGuardrailEvidenceSink(),
    });
    const out = await readAllText(
      screenSseBody(byteStreamFrom(chunks), {
        engine,
        context: chatContext({
          streaming: true,
          envelope: { protocol: "chat_completions", stage: "response", segments: [] },
        }),
        dialect: "openai.chat",
        protocol: "chat_completions",
        requestId: "fg-0000000000000001",
        onOutcome: (value) => {
          outcome = value;
        },
      }),
    );
    expect(outcome?.kind).toBe("blocked");
    expect(out).not.toContain(PROBE_SECRET);
    // No U+FFFD replacement character leaked from the split.
    expect(out).not.toContain("�");
  });

  test("the carry window is bounded — a very long clean prefix still streams", async () => {
    const long = "a".repeat(20_000);
    const { text, outcome } = screen([chatFrame(long), "data: [DONE]\n\n"]);
    const out = await text;
    expect(out).toContain(long);
    expect(outcome()).toEqual({ kind: "clean" });
  });
});

describe("mid-stream redaction", () => {
  test("the offending frame is rewritten and the stream continues", async () => {
    const { text, outcome } = screen(
      [
        chatFrame("token one "),
        chatFrame(`secret ${PROBE_SECRET} here`),
        chatFrame(" token three"),
        "data: [DONE]\n\n",
      ],
      RESPONSE_REDACT_POLICY,
    );
    const out = await text;

    expect(out).not.toContain(PROBE_SECRET);
    expect(out).toContain("[REDACTED]");
    // The stream was NOT terminated: later frames still arrive.
    expect(out).toContain(" token three");
    expect(out).toContain("[DONE]");
    expect(outcome()?.kind).toBe("redacted");
  });
});

describe("shadow streaming", () => {
  test("a shadow policy never rewrites or truncates the stream", async () => {
    const { text, outcome } = screen(
      [chatFrame(`leak ${PROBE_SECRET}`), "data: [DONE]\n\n"],
      secretScanPolicy({
        policyId: "stream-shadow",
        stage: "response",
        streaming: "shadow_after_complete",
      }),
    );
    const out = await text;
    // `shadow_after_complete` on a streaming response is `not_enforced`.
    expect(out).toContain(PROBE_SECRET);
    expect(outcome()).toEqual({ kind: "clean" });
  });
});

describe("evidence volume", () => {
  test("incremental screening writes ONE evidence row per policy, not one per frame", async () => {
    const evidence = new InMemoryGuardrailEvidenceSink();
    const engine = new GuardrailEngine({
      policies: sourceFor(RESPONSE_BLOCK_POLICY),
      evidence,
    });
    await readAllText(
      screenSseBody(
        byteStreamFrom([
          chatFrame("one"),
          chatFrame("two"),
          chatFrame("three"),
          "data: [DONE]\n\n",
        ]),
        {
          engine,
          context: chatContext({
            streaming: true,
            envelope: { protocol: "chat_completions", stage: "response", segments: [] },
          }),
          dialect: "openai.chat",
          protocol: "chat_completions",
          requestId: "fg-0000000000000001",
        },
      ),
    );
    expect(evidence.evaluations()).toHaveLength(1);
  });
});
