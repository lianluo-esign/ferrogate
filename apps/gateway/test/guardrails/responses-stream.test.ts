/**
 * RESPONSE-STAGE SCREENING OF EVERY MODEL-CONTENT FRAME ON `openai.responses`
 * (issue #778).
 *
 * `guardrails/stream.ts` used to read and patch exactly ONE event on this
 * dialect — `response.output_text.delta`. Every other frame that carries
 * model-generated text went past the response-stage policy untouched:
 *
 *  - `response.completed` (and `response.incomplete`), whose `response.output`
 *    holds the FULL assembled answer. This is the frame a client is most likely
 *    to treat as canonical, because it is the complete one;
 *  - `response.output_text.done`, which repeats the whole text;
 *  - `response.function_call_arguments.delta` / `.done` — tool-call arguments,
 *    which the sibling `openai.chat` arm HAS always screened, so the two
 *    surfaces disagreed about the same bytes;
 *  - `response.output_item.added` / `.done` and `response.content_part.done`.
 *
 * So both #680 (PII redaction) and #688 (injection defence) were bypassed on
 * the streaming Responses surface — the default posture for an interactive
 * agent.
 *
 * Every assertion below states the SURVIVING content as well as the absence of
 * the marker. "the secret is gone" is also true of a screener that drops the
 * whole frame, and dropping `response.completed` would trade a content leak for
 * a protocol break.
 */
import { describe, expect, test } from "vitest";
import {
  GuardrailEngine,
  InMemoryGuardrailEvidenceSink,
  type StreamScreenOutcome,
  screenSseBody,
} from "../../src/guardrails/index.js";
import { byteStreamFrom, parseSse, readAllText } from "../../src/streaming/sse.js";
import {
  FINGERPRINT_SECRET_REF,
  PROBE_SECRET,
  chatContext,
  secretScanPolicy,
  sourceFor,
} from "./fixtures.js";

const CARD = "4111111111111111";

const RESPONSES_REDACT_POLICY = secretScanPolicy({
  policyId: "responses-stream-redact",
  stage: "response",
  streaming: "buffer_and_enforce",
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "redacted" }],
});

const RESPONSES_BLOCK_POLICY = secretScanPolicy({
  policyId: "responses-stream-block",
  stage: "response",
  streaming: "buffer_and_enforce",
});

/** The native PII detector (#680), so the redaction under test is the shipped one. */
const RESPONSES_PII_POLICY = secretScanPolicy({
  policyId: "responses-stream-pii",
  stage: "response",
  streaming: "buffer_and_enforce",
  detector: {
    kind: "pii",
    entities: ["credit_card", "email"],
    redaction: "mask",
    fingerprint_secret_ref: FINGERPRINT_SECRET_REF,
  } as never,
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "pii redacted" }],
});

/** One `response.*` SSE frame, named on the `event:` line as OpenAI names it. */
function frame(event: string, payload: Record<string, unknown>): string {
  return `event: ${event}\ndata: ${JSON.stringify({ type: event, ...payload })}\n\n`;
}

/** A provider-relayed terminal frame carrying the complete assembled answer. */
function completedFrame(text: string): string {
  return frame("response.completed", {
    response: {
      id: "resp_778",
      status: "completed",
      output: [
        {
          type: "message",
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text }],
        },
      ],
      usage: { input_tokens: 3, output_tokens: 9, total_tokens: 12 },
    },
  });
}

function screen(
  chunks: readonly string[],
  policy = RESPONSES_REDACT_POLICY,
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
      envelope: { protocol: "responses", stage: "response", segments: [] },
    }),
    dialect: "openai.responses",
    protocol: "responses",
    requestId: "fg-0000000000000778",
    onOutcome: (value) => {
      outcome = value;
    },
  });
  return { text: readAllText(stream), outcome: () => outcome };
}

/** Every event name on the wire, in order. */
function events(sse: string): string[] {
  return parseSse(sse)
    .filter((f) => f.data !== undefined)
    .map((f) => f.event ?? (f.data === "[DONE]" ? "[DONE]" : ""));
}

/** The payload of the first frame with this event name. */
function payload(sse: string, event: string): Record<string, unknown> | undefined {
  for (const f of parseSse(sse)) {
    if (f.event === event && f.data !== undefined) {
      return JSON.parse(f.data) as Record<string, unknown>;
    }
  }
  return undefined;
}

/** `response.output[0].content[0].text` off a `response.completed` payload. */
function completedText(sse: string): string | undefined {
  const body = payload(sse, "response.completed");
  const response = body?.response as Record<string, unknown> | undefined;
  const output = response?.output as Array<{ content?: Array<{ text?: unknown }> }> | undefined;
  const text = output?.[0]?.content?.[0]?.text;
  return typeof text === "string" ? text : undefined;
}

describe("the terminal response.completed frame is screened (#778)", () => {
  test("a secret carried ONLY by the terminal frame is redacted in place", async () => {
    // The deltas are clean; the provider's terminal frame is where the marker
    // lives. This is the exact bypass the issue reports — nothing before this
    // frame ever tripped the policy.
    const { text, outcome } = screen([
      frame("response.output_text.delta", { delta: "here is " }),
      frame("response.output_text.delta", { delta: "the answer" }),
      completedFrame(`here is the answer ${PROBE_SECRET} done`),
      "data: [DONE]\n\n",
    ]);
    const out = await text;

    expect(out).not.toContain(PROBE_SECRET);
    // The frame is still delivered, and its STRUCTURE survives — the client's
    // completion semantics are intact, only the offending span is gone.
    expect(events(out)).toEqual([
      "response.output_text.delta",
      "response.output_text.delta",
      "response.completed",
      "[DONE]",
    ]);
    expect(completedText(out)).toBe("here is the answer [REDACTED] done");
    const response = payload(out, "response.completed")?.response as Record<string, unknown>;
    expect(response.id).toBe("resp_778");
    expect(response.usage).toEqual({ input_tokens: 3, output_tokens: 9, total_tokens: 12 });
    expect(outcome()?.kind).toBe("redacted");
  });

  test("a card in the terminal frame is masked by the native PII detector (#680)", async () => {
    const { text, outcome } = screen(
      [completedFrame(`your card ${CARD} was charged`), "data: [DONE]\n\n"],
      RESPONSES_PII_POLICY,
    );
    const out = await text;
    expect(out).not.toContain(CARD);
    expect(completedText(out)).toBe("your card [REDACTED:CREDIT_CARD] was charged");
    expect(outcome()?.kind).toBe("redacted");
  });

  test("a DENY on the terminal frame truncates the stream VISIBLY", async () => {
    // The deltas are already on the wire, so there is no status line left to
    // correct — #733 settled this for a failure after the headers are flushed:
    // fault the stream so the truncation is visible rather than ending it
    // cleanly and pretending. Here that means the offending `response.completed`
    // is NEVER forwarded and `response.failed` takes its place, so a caller can
    // tell "truncated by policy" from "complete" by the terminal event alone.
    const { text, outcome } = screen(
      [
        frame("response.output_text.delta", { delta: "here is " }),
        completedFrame(`here is ${PROBE_SECRET}`),
        "data: [DONE]\n\n",
      ],
      RESPONSES_BLOCK_POLICY,
    );
    const out = await text;

    expect(out).not.toContain(PROBE_SECRET);
    expect(events(out)).toEqual(["response.output_text.delta", "response.failed", "[DONE]"]);
    expect(events(out)).not.toContain("response.completed");
    expect(payload(out, "response.failed")).toEqual({
      request_id: "fg-0000000000000778",
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
      },
    });
    expect(outcome()?.kind).toBe("blocked");
  });

  test("a marker split across two content parts of ONE frame is caught", async () => {
    // The terminal frame can hold several text positions, and a screener that
    // evaluated each in isolation would miss a marker that spans two of them —
    // the within-frame twin of the across-frame straddle the carry window
    // exists for. All positions are joined into ONE segment for the detector,
    // and its offsets are mapped back onto the position they landed in.
    const head = PROBE_SECRET.slice(0, 8);
    const tail = PROBE_SECRET.slice(8);
    const { text } = screen([
      frame("response.completed", {
        response: {
          id: "resp_778",
          output: [
            {
              type: "message",
              role: "assistant",
              content: [
                { type: "output_text", text: `key ${head}` },
                { type: "output_text", text: `${tail} done` },
              ],
            },
          ],
        },
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    // The replacement lands ONCE, in the first position the finding touched,
    // and the straddled range is removed from the second — not duplicated into
    // both, and not left behind in either.
    const response = payload(out, "response.completed")?.response as {
      output: Array<{ content: Array<{ text: string }> }>;
    };
    expect(response.output[0]?.content.map((part) => part.text)).toEqual([
      "key [REDACTED]",
      " done",
    ]);
  });

  test("response.incomplete carries the same output and is screened the same way", async () => {
    const { text } = screen([
      frame("response.incomplete", {
        response: {
          id: "resp_778",
          status: "incomplete",
          output: [
            {
              type: "message",
              role: "assistant",
              content: [{ type: "output_text", text: `cut off ${PROBE_SECRET}` }],
            },
          ],
        },
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    expect(out).toContain("cut off [REDACTED]");
  });
});

describe("the sibling frames on this protocol (#778)", () => {
  test("response.output_text.done repeats the whole text and is screened", async () => {
    const { text } = screen([
      frame("response.output_text.done", { text: `all of it ${PROBE_SECRET}` }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    expect(payload(out, "response.output_text.done")?.text).toBe("all of it [REDACTED]");
  });

  test("tool-call arguments are screened on this dialect, as they are on openai.chat", async () => {
    // `frameText`'s `openai.chat` arm has always folded `tool_calls[].function.
    // arguments` into the screened text. The Responses spelling of the same
    // bytes went unscreened, so the SAME model output leaked or not depending
    // on which ingress dialect the caller happened to use.
    const { text } = screen([
      frame("response.function_call_arguments.delta", {
        delta: `{"key":"${PROBE_SECRET}"}`,
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    expect(payload(out, "response.function_call_arguments.delta")?.delta).toBe(
      '{"key":"[REDACTED]"}',
    );
  });

  test("the accumulated tool-call arguments frame is screened too", async () => {
    const { text } = screen([
      frame("response.function_call_arguments.done", {
        call_id: "call_1",
        name: "search",
        arguments: `{"key":"${PROBE_SECRET}"}`,
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    const body = payload(out, "response.function_call_arguments.done");
    expect(body?.arguments).toBe('{"key":"[REDACTED]"}');
    // The routing members a client needs to attribute the call survive.
    expect(body?.call_id).toBe("call_1");
    expect(body?.name).toBe("search");
  });

  test("response.output_item.done carries a whole item and is screened", async () => {
    const { text } = screen([
      frame("response.output_item.done", {
        output_index: 0,
        item: {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: `item text ${PROBE_SECRET}` }],
        },
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    expect(out).toContain("item text [REDACTED]");
  });

  test("response.content_part.done carries a part and is screened", async () => {
    const { text } = screen([
      frame("response.content_part.done", {
        content_index: 0,
        part: { type: "output_text", text: `part text ${PROBE_SECRET}` },
      }),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(PROBE_SECRET);
    expect(out).toContain("part text [REDACTED]");
  });

  test("a refusal is model content too", async () => {
    const { text } = screen([
      frame("response.refusal.done", { refusal: `I cannot: ${PROBE_SECRET}` }),
      "data: [DONE]\n\n",
    ]);
    expect(await text).not.toContain(PROBE_SECRET);
  });

  test("a reasoning summary is model content too", async () => {
    const { text } = screen([
      frame("response.reasoning_summary_text.delta", { delta: `thinking ${PROBE_SECRET}` }),
      "data: [DONE]\n\n",
    ]);
    expect(await text).not.toContain(PROBE_SECRET);
  });
});

describe("SSE plumbing is still never screened (#778)", () => {
  test("the synthesized usage-only response.completed passes through untouched", async () => {
    // `streaming/responses.ts` emits a terminal frame carrying only usage. It
    // has no model text, so it must not reach a detector at all — a needless
    // evidence row and a false-positive surface.
    const evidence = new InMemoryGuardrailEvidenceSink();
    const engine = new GuardrailEngine({
      policies: sourceFor(RESPONSES_REDACT_POLICY),
      evidence,
    });
    const out = await readAllText(
      screenSseBody(
        byteStreamFrom([
          frame("response.completed", {
            request_id: "fg-0000000000000778",
            content_type: "text/event-stream",
            usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
          }),
          "data: [DONE]\n\n",
        ]),
        {
          engine,
          context: chatContext({
            streaming: true,
            envelope: { protocol: "responses", stage: "response", segments: [] },
          }),
          dialect: "openai.responses",
          protocol: "responses",
          requestId: "fg-0000000000000778",
        },
      ),
    );
    expect(payload(out, "response.completed")).toEqual({
      type: "response.completed",
      request_id: "fg-0000000000000778",
      content_type: "text/event-stream",
      usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    });
    expect(evidence.evaluations()).toHaveLength(0);
  });

  test("a clean terminal frame is not rewritten — no over-redaction", async () => {
    const { text, outcome } = screen([
      completedFrame("order 1234567890123456 shipped on Tuesday"),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(completedText(out)).toBe("order 1234567890123456 shipped on Tuesday");
    expect(outcome()).toEqual({ kind: "clean" });
  });
});
