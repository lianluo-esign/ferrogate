/**
 * NATIVE PII DETECTION AND REDACTION (issue #680).
 *
 * The property under test is not "something got redacted". A redactor that
 * blanks the whole document also makes that assertion pass, and a bare
 * 16-digit regex also makes "the card was found" pass while flagging every
 * order number a customer ever pastes. So every case here asserts BOTH sides:
 *
 *  - the PII is gone AND the surrounding text survived byte-for-byte;
 *  - the true positive fires AND the near-miss with a broken checksum does NOT.
 *
 * The false-negative direction is the dangerous one: a detector that silently
 * misses converts an open risk into a false assurance, which is why the
 * chunk-straddle case and the per-protocol coverage case are here at all.
 */
import { describe, expect, test } from "vitest";
import {
  type ContentSegment,
  type DetectorInput,
  DetectorSecret,
  type GuardrailProtocol,
  InMemoryPiiTokenVault,
  PII_ENTITIES,
  PiiDetector,
  type PiiEntity,
  type WorkersAiClient,
  applyContentPatchesToDocument,
  contentFingerprint,
  normalizeRequest,
} from "../src/index.js";

const KEY = DetectorSecret.new("evidence-key");
const DEADLINE = () => Date.now() + 5_000;

// Synthetic values. Every one is a published test vector or a checksum-valid
// construction; none belongs to a person.
const CARD = "4111111111111111"; // Luhn-valid Visa test number
const ORDER_NO = "1234567890123456"; // 16 digits, Luhn-INVALID: an order number
const SSN = "123-45-6789";
const IBAN = "GB82WEST12345698765432";
const CN_ID = "11010519491231002X";
const EMAIL = "jane.doe@example.com";
const E164 = "+14155552671";

function detector(overrides: Partial<Parameters<typeof PiiDetector.new>[0]> = {}): PiiDetector {
  return PiiDetector.new({
    id: "pii",
    supported_sources: ["system", "developer", "user", "assistant", "tool_result"],
    entities: [...PII_ENTITIES],
    redaction: "mask",
    fingerprint_key: KEY,
    ...overrides,
  });
}

function chatInput(text: string): DetectorInput {
  const envelope = normalizeRequest("chat_completions", {
    messages: [{ role: "user", content: text }],
  });
  return {
    protocol: envelope.protocol,
    stage: envelope.stage,
    tenant: { organization_id: "org" },
    text: "",
    segments: envelope.segments,
  };
}

/** Apply the detector's own patches back onto the chat document. */
async function redactChat(det: PiiDetector, text: string): Promise<string> {
  const body = { messages: [{ role: "user", content: text }] };
  const envelope = normalizeRequest("chat_completions", body);
  const result = await det.evaluate(
    {
      protocol: envelope.protocol,
      stage: envelope.stage,
      tenant: { organization_id: "org" },
      text: "",
      segments: envelope.segments,
    },
    DEADLINE(),
  );
  const patched = applyContentPatchesToDocument(
    body,
    envelope,
    ["system", "developer", "user", "assistant", "tool_result"],
    result.patches,
  ) as { messages: Array<{ content: string }> };
  return patched.messages[0]?.content ?? "";
}

async function categories(det: PiiDetector, text: string): Promise<string[]> {
  const result = await det.evaluate(chatInput(text), DEADLINE());
  return result.findings.map((f) => f.category).sort();
}

// ---------------------------------------------------------------------------
// Validators: the true positive AND the near-miss
// ---------------------------------------------------------------------------

describe("validated pattern pack", () => {
  const det = detector();

  test("a Luhn-valid card is a critical, keyed, non-quoting finding", async () => {
    const result = await det.evaluate(chatInput(`charge ${CARD} today`), DEADLINE());
    expect(result.verdict).toBe("fail");
    const finding = result.findings.find((f) => f.category === "pii.credit_card");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(finding?.fingerprint).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    // Evidence must never quote the value it caught.
    expect(finding?.matched_text).toBeNull();
    expect(JSON.stringify(result)).not.toContain(CARD);
  });

  test("a 16-digit ORDER NUMBER is not a card — Luhn is load-bearing", async () => {
    const result = await det.evaluate(chatInput(`order ${ORDER_NO} shipped`), DEADLINE());
    expect(result.findings.map((f) => f.category)).not.toContain("pii.credit_card");
    expect(result.verdict).toBe("pass");
  });

  test("separators do not hide a card, and evidence correlates across spellings", async () => {
    const spaced = await det.evaluate(chatInput("charge 4111 1111 1111 1111 today"), DEADLINE());
    const dashed = await det.evaluate(chatInput("charge 4111-1111-1111-1111 today"), DEADLINE());
    const bare = await det.evaluate(chatInput(`charge ${CARD} today`), DEADLINE());
    const fp = (r: Awaited<ReturnType<PiiDetector["evaluate"]>>) =>
      r.findings.find((f) => f.category === "pii.credit_card")?.fingerprint;
    expect(fp(spaced)).toBeDefined();
    expect(fp(spaced)).toBe(fp(bare));
    expect(fp(dashed)).toBe(fp(bare));
  });

  test.each([
    ["000-45-6789", "area 000"],
    ["666-45-6789", "area 666"],
    ["900-45-6789", "area 9xx"],
    ["123-00-6789", "group 00"],
    ["123-45-0000", "serial 0000"],
  ])("SSN %s is rejected (%s)", async (value) => {
    expect(await categories(det, `id ${value} on file`)).not.toContain("pii.us_ssn");
  });

  test("a structurally valid SSN is caught", async () => {
    expect(await categories(det, `id ${SSN} on file`)).toContain("pii.us_ssn");
  });

  test("IBAN mod-97 separates the real one from the typo", async () => {
    expect(await categories(det, `pay ${IBAN}`)).toContain("pii.iban");
    expect(await categories(det, "pay GB82WEST12345698765431")).not.toContain("pii.iban");
  });

  test("CN resident id MOD 11-2 separates the real one from the typo", async () => {
    expect(await categories(det, `身份证 ${CN_ID}`)).toContain("pii.cn_resident_id");
    expect(await categories(det, "身份证 110105194912310021")).not.toContain("pii.cn_resident_id");
  });

  test("email requires a real TLD", async () => {
    expect(await categories(det, `mail ${EMAIL}`)).toContain("pii.email");
    expect(await categories(det, "mail root@localhost")).not.toContain("pii.email");
    expect(await categories(det, "mail a@b.c")).not.toContain("pii.email");
  });

  test("phone: E.164 and NANP, but not a short code or a 1xx area", async () => {
    expect(await categories(det, `call ${E164}`)).toContain("pii.phone");
    expect(await categories(det, "call 415-555-2671")).toContain("pii.phone");
    expect(await categories(det, "call +1234")).not.toContain("pii.phone");
    expect(await categories(det, "call 115-555-2671")).not.toContain("pii.phone");
  });

  test("a benign prompt produces nothing at all", async () => {
    const result = await det.evaluate(
      chatInput("Summarise the Q3 revenue deck in three bullets."),
      DEADLINE(),
    );
    expect(result.verdict).toBe("pass");
    expect(result.findings).toEqual([]);
    expect(result.patches).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Redaction: reversible or irreversible BY POLICY
// ---------------------------------------------------------------------------

describe("redaction policy", () => {
  test("mask is irreversible and leaves every non-PII byte in place", async () => {
    const out = await redactChat(detector({ redaction: "mask" }), `charge ${CARD} today please`);
    expect(out).toBe("charge [REDACTED:CREDIT_CARD] today please");
    expect(out).not.toContain(CARD);
  });

  test("pseudonymize is stable under a key and unrecoverable without the value", async () => {
    const a = await redactChat(detector({ redaction: "pseudonymize" }), `charge ${CARD}`);
    const b = await redactChat(detector({ redaction: "pseudonymize" }), `bill ${CARD}`);
    const other = await redactChat(
      detector({ redaction: "pseudonymize", fingerprint_key: DetectorSecret.new("other-key") }),
      `charge ${CARD}`,
    );
    expect(a).toMatch(/^charge \[CREDIT_CARD:hmac-sha256:[0-9a-f]{16}\]$/);
    // Same value, same key ⇒ same pseudonym (that is the point of the mode).
    expect(a.slice("charge ".length)).toBe(b.slice("bill ".length));
    // Different key ⇒ different pseudonym: the mapping is not a bare digest.
    expect(other).not.toBe(a);
    expect(a).not.toContain(CARD);
  });

  test("tokenize is REVERSIBLE — and only with the vault", async () => {
    const vault = new InMemoryPiiTokenVault();
    const det = detector({ redaction: "tokenize", vault });
    const out = await redactChat(det, `charge ${CARD} today`);
    expect(out).toMatch(/^charge \[CREDIT_CARD:tok_[0-9a-f]{24}\] today$/);
    expect(out).not.toContain(CARD);
    expect(vault.size).toBe(1);
    expect(vault.restore(out)).toBe(`charge ${CARD} today`);
    // A different vault cannot reverse it.
    expect(new InMemoryPiiTokenVault().restore(out)).toBe(out);
  });

  test("reversibility is never accidental: tokenize without a vault refuses to build", () => {
    expect(() => detector({ redaction: "tokenize" })).toThrowError(
      /reversible .*vault|vault.*reversible/i,
    );
  });

  test("an irreversible mode may not be handed a vault to quietly fill", () => {
    expect(() => detector({ redaction: "mask", vault: new InMemoryPiiTokenVault() })).toThrow();
  });

  test.each(["mask", "pseudonymize", "tokenize"] as const)(
    "%s replacements are JSON-string safe",
    async (mode) => {
      const vault = mode === "tokenize" ? new InMemoryPiiTokenVault() : undefined;
      const det = detector({ redaction: mode, ...(vault ? { vault } : {}) });
      const result = await det.evaluate(chatInput(`a ${CARD} b ${EMAIL}`), DEADLINE());
      expect(result.patches.length).toBeGreaterThan(0);
      for (const patch of result.patches) {
        // A quote, a backslash or a control character is exactly what would
        // break a JSON string literal the placeholder is spliced into.
        // biome-ignore lint/suspicious/noControlCharactersInRegex: that IS the assertion
        expect(patch.replacement).not.toMatch(/["\\\u0000-\u001f]/);
      }
    },
  );

  test("redacting inside a JSON string leaves the JSON parseable", async () => {
    // A tool result whose text IS a JSON document — the shape where a careless
    // replacement (a quote, a backslash) turns a redaction into a parse error
    // downstream.
    const payload = JSON.stringify({ customer: EMAIL, order: ORDER_NO, note: "keep me" });
    const out = await redactChat(detector(), payload);
    const parsed = JSON.parse(out) as Record<string, unknown>;
    expect(parsed.customer).toBe("[REDACTED:EMAIL]");
    // Structure and the non-PII siblings survive — the redactor did not blank.
    expect(parsed.order).toBe(ORDER_NO);
    expect(parsed.note).toBe("keep me");
  });
});

// ---------------------------------------------------------------------------
// Streaming: a secret straddling a chunk boundary
// ---------------------------------------------------------------------------

describe("chunk straddle", () => {
  function segment(id: string, text: string): ContentSegment {
    return {
      segment_id: id,
      source: "assistant",
      protocol_location: `response.stream.${id}`,
      content_type: "text",
      text,
      fingerprint: contentFingerprint(text),
    };
  }

  test("a card split across two adjacent chunks is still caught and fully covered", async () => {
    // `41111111` | `11111111` — neither half is a card; the join is.
    const segments = [segment("carry", "charge 41111111"), segment("delta", "11111111 today")];
    const result = await detector().evaluate(
      {
        protocol: "chat_completions",
        stage: "response",
        tenant: {},
        text: "",
        segments,
      },
      DEADLINE(),
    );
    expect(result.verdict).toBe("fail");
    expect(result.findings.map((f) => f.category)).toContain("pii.credit_card");
    // BOTH halves must be patched, or the already-forwarded chunk keeps its
    // half of the card and the redaction was cosmetic.
    const patched = new Set(result.patches.map((p) => p.segment_id));
    expect(patched).toEqual(new Set(["carry", "delta"]));
    // And the surviving text is exactly the non-PII text.
    const apply = (seg: ContentSegment): string => {
      let out = seg.text;
      for (const patch of result.patches
        .filter((p) => p.segment_id === seg.segment_id)
        .sort((a, b) => b.byte_start - a.byte_start)) {
        out = out.slice(0, patch.byte_start) + patch.replacement + out.slice(patch.byte_end);
      }
      return out;
    };
    expect(apply(segments[0] as ContentSegment)).toBe("charge [REDACTED:CREDIT_CARD]");
    expect(apply(segments[1] as ContentSegment)).toBe("[REDACTED:CREDIT_CARD] today");
  });

  test("neither half alone trips the detector (the join is what matters)", async () => {
    expect(await categories(detector(), "charge 41111111")).toEqual([]);
    expect(await categories(detector(), "11111111 today")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Every shape the gateway carries
// ---------------------------------------------------------------------------

describe("protocol coverage", () => {
  // One realistic body per bound gateway operation
  // (`apps/gateway/src/guardrails/middleware.ts::GUARDRAIL_OPERATIONS`). A
  // protocol whose extractor yields an empty envelope screens NOTHING and does
  // it silently — the #676 rerank hole, in the general case.
  const bodies: Array<[GuardrailProtocol, string, unknown]> = [
    [
      "chat_completions",
      "string content",
      { messages: [{ role: "user", content: `pay ${CARD}` }] },
    ],
    [
      "chat_completions",
      "content parts",
      { messages: [{ role: "user", content: [{ type: "text", text: `pay ${CARD}` }] }] },
    ],
    ["responses", "string input", { input: `pay ${CARD}` }],
    [
      "responses",
      "input items",
      { input: [{ role: "user", content: [{ type: "input_text", text: `pay ${CARD}` }] }] },
    ],
    ["responses", "instructions", { instructions: `pay ${CARD}`, input: "hello" }],
    ["embeddings", "string input", { input: `pay ${CARD}` }],
    ["embeddings", "array input", { input: ["hello", `pay ${CARD}`] }],
    ["rerank", "query", { query: `pay ${CARD}`, documents: ["a"] }],
    ["rerank", "plain documents", { query: "q", documents: [`pay ${CARD}`] }],
    ["rerank", "object documents", { query: "q", documents: [{ text: `pay ${CARD}` }] }],
    ["images", "prompt", { prompt: `pay ${CARD}` }],
  ];

  test.each(bodies)("%s (%s) is screened, not silently empty", async (protocol, _label, body) => {
    const envelope = normalizeRequest(protocol, body);
    expect(envelope.segments.length).toBeGreaterThan(0);
    const result = await detector().evaluate(
      {
        protocol: envelope.protocol,
        stage: envelope.stage,
        tenant: {},
        text: "",
        segments: envelope.segments,
      },
      DEADLINE(),
    );
    expect(result.findings.map((f) => f.category)).toContain("pii.credit_card");
    expect(result.patches.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Auditability without recreating the leak
// ---------------------------------------------------------------------------

describe("audit hygiene", () => {
  test("no finding quotes any PII, and the fingerprint is keyed", async () => {
    const text = `${CARD} ${SSN} ${IBAN} ${CN_ID} ${EMAIL} ${E164}`;
    const mine = await detector().evaluate(chatInput(text), DEADLINE());
    const theirs = await detector({ fingerprint_key: DetectorSecret.new("other") }).evaluate(
      chatInput(text),
      DEADLINE(),
    );
    const serialized = JSON.stringify(mine);
    for (const value of [CARD, SSN, IBAN, CN_ID, EMAIL, E164]) {
      expect(serialized).not.toContain(value);
    }
    for (const finding of mine.findings) {
      expect(finding.matched_text).toBeNull();
      expect(JSON.stringify(finding.attributes)).not.toContain(CARD);
    }
    // Keyed, not a bare digest: a different key must move every fingerprint.
    const mineFps = mine.findings.map((f) => f.fingerprint);
    const theirsFps = theirs.findings.map((f) => f.fingerprint);
    expect(mineFps.length).toBeGreaterThan(0);
    expect(mineFps).not.toEqual(theirsFps);
  });

  test("every configured entity is actually reachable", async () => {
    const found = await categories(detector(), `${CARD} ${SSN} ${IBAN} ${CN_ID} ${EMAIL} ${E164}`);
    for (const entity of PII_ENTITIES) {
      expect(found).toContain(`pii.${entity satisfies PiiEntity}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Bounds and fail-closed
// ---------------------------------------------------------------------------

describe("bounds", () => {
  test("an expired deadline is a timeout, never a pass", async () => {
    await expect(detector().evaluate(chatInput("hi"), Date.now() - 1)).rejects.toMatchObject({
      kind: "timeout",
    });
  });

  test("oversize input fails closed with a size finding", async () => {
    const result = await detector({ max_input_bytes: 8 }).evaluate(
      chatInput("this is comfortably more than eight bytes"),
      DEADLINE(),
    );
    expect(result.verdict).toBe("fail");
    expect(result.findings.map((f) => f.category)).toContain("size.input_bytes");
  });

  test("an empty entity list refuses to build", () => {
    expect(() => detector({ entities: [] })).toThrow();
  });

  test("keyed evidence is mandatory", () => {
    expect(() =>
      PiiDetector.new({
        id: "pii",
        supported_sources: ["user"],
        entities: ["email"],
        redaction: "mask",
      } as never),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// The OPTIONAL Workers AI stage — for the entities no grammar can reach
// ---------------------------------------------------------------------------

describe("workers ai stage", () => {
  /** A Workers AI client scripted to answer with `spans`, in the wire shape. */
  function aiClient(spans: Array<{ type: string; text: string }>): WorkersAiClient {
    return {
      run: async () => ({ response: `Sure! ${JSON.stringify({ entities: spans })}` }),
    };
  }

  function withAi(client: WorkersAiClient, timeoutMs = 1_000): PiiDetector {
    return detector({
      ai: { client, entities: ["person", "postal_address", "organization"], timeoutMs },
    });
  }

  test("a name the pattern pack cannot reach is found and redacted", async () => {
    const det = withAi(aiClient([{ type: "person", text: "Dr. Ada Lovelace" }]));
    const out = await redactChat(det, "book a call with Dr. Ada Lovelace on Tuesday");
    expect(out).toBe("book a call with [REDACTED:PERSON] on Tuesday");
  });

  test("a HALLUCINATED span redacts nothing — the model proposes, the text disposes", async () => {
    // The model returns a name that never appears in the input. Trusting it
    // would blank bytes the user never wrote, at an offset the model chose.
    const det = withAi(aiClient([{ type: "person", text: "Grace Hopper" }]));
    const text = "book a call with Dr. Ada Lovelace on Tuesday";
    const result = await det.evaluate(chatInput(text), DEADLINE());
    expect(result.findings.map((f) => f.category)).not.toContain("pii.person");
    expect(result.patches).toEqual([]);
    expect(await redactChat(det, text)).toBe(text);
  });

  test("an entity type the policy did not enable is ignored", async () => {
    const det = detector({
      ai: {
        client: aiClient([{ type: "organization", text: "Acme Corp" }]),
        entities: ["person"],
        timeoutMs: 1_000,
      },
    });
    const text = "invoice Acme Corp please";
    expect(await redactChat(det, text)).toBe(text);
  });

  test("an unreachable model FAILS CLOSED — never a clean pass", async () => {
    const det = withAi({ run: async () => Promise.reject(new Error("AI binding unavailable")) });
    await expect(det.evaluate(chatInput("hello there"), DEADLINE())).rejects.toMatchObject({
      kind: "unavailable",
    });
  });

  test("a hung model is a timeout, not a pass", async () => {
    const det = withAi({ run: () => new Promise(() => {}) }, 10);
    await expect(det.evaluate(chatInput("hello there"), DEADLINE())).rejects.toMatchObject({
      kind: "timeout",
    });
  });

  test("a chatty or malformed model answer cannot erase the deterministic findings", async () => {
    const det = withAi({ run: async () => ({ response: "I am not going to answer that." }) });
    const result = await det.evaluate(chatInput(`charge ${CARD}`), DEADLINE());
    expect(result.findings.map((f) => f.category)).toContain("pii.credit_card");
  });

  test("enabling the stage is declared on the descriptor's residency", () => {
    expect(detector().descriptor().data_residency).toBe("in_repo");
    expect(withAi(aiClient([])).descriptor().data_residency).toBe("provider_saas");
  });
});
