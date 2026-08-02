/**
 * NATIVE PII REDACTION ON A STREAMING RESPONSE (issue #680).
 *
 * The interesting case is not "a card in one frame". It is a card that STRADDLES
 * a frame boundary: the model emits `…4111` in one chunk and `111111111111` in
 * the next, neither half is a card, and a screener that looks at one frame at a
 * time forwards both — a clean-looking stream that leaked a card number.
 *
 * `screenSseFrames` already carries a bounded overlap window for exactly this
 * reason. What this file pins is that the PII detector participates in it:
 * `PiiDetector` uses `deterministic.ts`'s own coalescer, so the carry+delta pair
 * the screener builds is joined before matching. If the two detectors ever drift
 * on that, this file goes red rather than a customer's card going out.
 *
 * Every assertion states the SURVIVING text too. "the card is gone" is also true
 * of a screener that drops the whole stream.
 */
import { describe, expect, test } from "vitest";
import {
  GuardrailEngine,
  InMemoryGuardrailEvidenceSink,
  type StreamScreenOutcome,
  screenSseBody,
} from "../../src/guardrails/index.js";
import { byteStreamFrom, parseSse, readAllText } from "../../src/streaming/sse.js";
import { FINGERPRINT_SECRET_REF, chatContext, secretScanPolicy, sourceFor } from "./fixtures.js";

const CARD = "4111111111111111";

/** A response-stage policy whose only check is the native PII detector. */
const PII_REDACT_POLICY = secretScanPolicy({
  policyId: "pii-stream-redact",
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

function chatFrame(content: string): string {
  return `data: ${JSON.stringify({
    id: "chatcmpl-1",
    object: "chat.completion.chunk",
    choices: [{ index: 0, delta: { content } }],
  })}\n\n`;
}

function screen(chunks: readonly string[]): {
  text: Promise<string>;
  outcome: () => StreamScreenOutcome | undefined;
} {
  let outcome: StreamScreenOutcome | undefined;
  const engine = new GuardrailEngine({
    policies: sourceFor(PII_REDACT_POLICY),
    evidence: new InMemoryGuardrailEvidenceSink(),
  });
  const stream = screenSseBody(byteStreamFrom([...chunks]), {
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
  });
  return { text: readAllText(stream), outcome: () => outcome };
}

/** The concatenated `delta.content` the client would render. */
function rendered(sse: string): string {
  let out = "";
  for (const frame of parseSse(sse)) {
    if (frame.data === undefined || frame.data === "[DONE]") {
      continue;
    }
    const json = JSON.parse(frame.data) as {
      choices?: Array<{ delta?: { content?: unknown } }>;
    };
    for (const choice of json.choices ?? []) {
      if (typeof choice.delta?.content === "string") {
        out += choice.delta.content;
      }
    }
  }
  return out;
}

describe("streaming PII redaction", () => {
  test("a card WHOLLY inside one frame is redacted and the rest streams on", async () => {
    const { text, outcome } = screen([
      chatFrame("your card "),
      chatFrame(CARD),
      chatFrame(" was charged"),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    expect(out).not.toContain(CARD);
    expect(rendered(out)).toBe("your card [REDACTED:CREDIT_CARD] was charged");
    expect(outcome()?.kind).toBe("redacted");
  });

  test("a card SPLIT across two frames is caught by the carry window", async () => {
    // `41111111` | `11111111` — neither half is a card number, and a screener
    // that evaluated each frame in isolation would forward both.
    const { text, outcome } = screen([
      chatFrame("your card 41111111"),
      chatFrame("11111111 was charged"),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    // The complete value never appears on the wire.
    expect(out).not.toContain(CARD);
    expect(outcome()?.kind).toBe("redacted");
    // STATED EXACTLY, because it is a limitation and not a success: frame 0 was
    // already forwarded when it was still a harmless digit run, and an
    // incremental screener cannot recall bytes it has delivered. What it CAN do
    // is mask the tail — which is what the carry window buys — so the client
    // ends up with the prefix and never the whole number. A deployment that
    // cannot accept a delivered PREFIX must use `reject_streaming`, which
    // refuses the streaming request before dispatch; that is the only posture
    // that buffers, and it costs the streaming UX.
    expect(rendered(out)).toBe("your card 41111111[REDACTED:CREDIT_CARD] was charged");
  });

  test("the split card is a real finding, not a coincidence of the tail frame", async () => {
    // Guards the assertion above from becoming vacuous: WITHOUT the carry join,
    // frame 1's own text (`11111111 was charged`) has no card in it and nothing
    // would be redacted at all.
    const { text } = screen([chatFrame("11111111 was charged"), "data: [DONE]\n\n"]);
    expect(rendered(await text)).toBe("11111111 was charged");
  });

  test("a clean stream is not touched — no over-redaction", async () => {
    const { text, outcome } = screen([
      chatFrame("order 1234567890123456 "),
      chatFrame("shipped on Tuesday"),
      "data: [DONE]\n\n",
    ]);
    const out = await text;
    // A Luhn-invalid 16-digit order number is NOT a card, mid-stream either.
    expect(rendered(out)).toBe("order 1234567890123456 shipped on Tuesday");
    expect(outcome()).toEqual({ kind: "clean" });
  });

  test("the raw value never reaches the evidence sink", async () => {
    const evidence = new InMemoryGuardrailEvidenceSink();
    const engine = new GuardrailEngine({ policies: sourceFor(PII_REDACT_POLICY), evidence });
    const stream = screenSseBody(byteStreamFrom([chatFrame(`card ${CARD}`), "data: [DONE]\n\n"]), {
      engine,
      context: chatContext({
        streaming: true,
        envelope: { protocol: "chat_completions", stage: "response", segments: [] },
      }),
      dialect: "openai.chat",
      protocol: "chat_completions",
      requestId: "fg-0000000000000001",
    });
    await readAllText(stream);
    const rows = evidence.serialized();
    expect(rows).not.toContain(CARD);
    // ...and the evidence is not empty, or the assertion above is vacuous.
    expect(evidence.evaluations().length).toBeGreaterThan(0);
    expect(rows).toContain("hmac-sha256:");
  });
});
