/**
 * THE KEYING GATE for guardrail evidence fingerprints.
 *
 * Closes `PORT-TODO(cutover-parity-libraries §4.4)`: every pre-existing
 * fingerprint assertion in this repository is a SHAPE assertion
 * (`/^hmac-sha256:[0-9a-f]{64}$/`), and an *unkeyed* SHA-256 satisfies that
 * shape exactly as well as a keyed HMAC does. The cutover audit proved the hole
 * by mutation: replacing `key.asBytes()` with `new Uint8Array(0)` in
 * `hmacEvidenceFingerprint`, and replacing the key with a hard-coded constant in
 * `DeterministicDetector#hmacFingerprint`, each left 407/407 guardrails tests and
 * 112/112 `apps/gateway/test/guardrails/` tests GREEN.
 *
 * Why an unkeyed digest is a real defect and not a style preference: the values
 * fingerprinted here are short and low-entropy — an API-key fragment, a name, an
 * account number, a prompt. `sha256(value)` of such a value is reversible by
 * dictionary/rainbow attack, so "correlatable but not reversible" collapses to
 * "reversible". The secret key is the whole of the non-reversibility.
 *
 * The four degradations gated here, each asserted by name:
 *
 *  1. **key IGNORED / swapped for a constant** — two detectors configured with
 *     DIFFERENT keys must produce DIFFERENT fingerprints for the SAME input.
 *  2. **fingerprint no longer a function of the key at all (plain digest)** —
 *     the fingerprint must NOT equal `hmac-sha256:` + the unkeyed SHA-256 of the
 *     input, and must NOT equal the empty-key HMAC of the input.
 *  3. **fingerprint stops being reproducible** (salted/random/nonced) — the same
 *     key over the same input must yield the same fingerprint, across separate
 *     detector instances and separate evaluations.
 *  4. **evidence persisted** — `matched_text` must stay null and neither the raw
 *     sensitive value nor the key may appear in the serialized result.
 *
 * The oracle is `node:crypto`, deliberately: an INDEPENDENT HMAC implementation.
 * Pinning against this package's own `hmacSha256` would let a mutation inside
 * `hash.ts` move both sides of the equality at once.
 */
import { createHash, createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  type DetectorInput,
  DetectorSecret,
  DeterministicDetector,
  FixtureTransport,
  type LlmGuardPromptInjectionConfig,
  LlmGuardPromptInjectionDetector,
  PresidioDetector,
  type PresidioDetectorConfig,
  WORKERS_AI_LLAMA_GUARD_DEFAULT_MODEL,
  type WorkersAiClient,
  type WorkersAiLlamaGuardConfig,
  WorkersAiLlamaGuardDetector,
  envelopeFromText,
  hmacEvidenceFingerprint,
  normalizeRequest,
} from "../src/index.js";

const DEADLINE = () => Date.now() + 5_000;

/* -- independent oracles (node:crypto, NOT this package's hash.ts) ---------- */

/** The correct, keyed evidence fingerprint for `value` under `key`. */
function keyedOracle(key: string, value: string): string {
  return `hmac-sha256:${createHmac("sha256", key).update(value, "utf8").digest("hex")}`;
}

/** Degradation 2a: the keying dropped entirely — a plain digest of the value. */
function unkeyedDigestOracle(value: string): string {
  return `hmac-sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

/** Degradation 2b: `key.asBytes()` → `new Uint8Array(0)` — HMAC under no key. */
function emptyKeyOracle(value: string): string {
  return `hmac-sha256:${createHmac("sha256", Buffer.alloc(0)).update(value, "utf8").digest("hex")}`;
}

const KEY_A = "tenant-a-evidence-key";
const KEY_B = "tenant-b-evidence-key";

/**
 * The shared shape assertion the OLD tests stopped at. Every negative below is
 * additionally asserted to still satisfy it — proof that shape alone cannot
 * separate a keyed fingerprint from any of the degradations.
 */
const SHAPE = /^hmac-sha256:[0-9a-f]{64}$/;

function userInput(text: string): DetectorInput {
  const env = envelopeFromText("chat_completions", "request", "user", "messages[0].content", text);
  return {
    protocol: "chat_completions",
    stage: "request",
    tenant: { organization_id: "o" },
    text,
    segments: env.segments,
  };
}

/* ==========================================================================
 * 0. The premise: the shape assertion the tree relied on is satisfied by all
 *    three degradations, so it can never have held the keying.
 * ========================================================================== */

describe("the pre-existing shape assertion cannot hold the keying", () => {
  test("keyed, unkeyed-digest and empty-key fingerprints all match /^hmac-sha256:[0-9a-f]{64}$/", () => {
    const value = "sentinel-value";
    expect(keyedOracle(KEY_A, value)).toMatch(SHAPE);
    expect(unkeyedDigestOracle(value)).toMatch(SHAPE);
    expect(emptyKeyOracle(value)).toMatch(SHAPE);
    // ...and they are three genuinely different strings, so a test that only
    // checks the shape passes for all three.
    expect(
      new Set([keyedOracle(KEY_A, value), unkeyedDigestOracle(value), emptyKeyOracle(value)]).size,
    ).toBe(3);
  });
});

/* ==========================================================================
 * SITE 1 — `hmacEvidenceFingerprint` (adapters/transport.ts).
 * Used by the Presidio, LLM-Guard and Workers-AI Llama-Guard adapters.
 * ========================================================================== */

describe("SITE 1 hmacEvidenceFingerprint — the shared adapter helper", () => {
  const VALUE = "a@b.com";

  test("1. different keys ⇒ different fingerprints for the same input", () => {
    const a = hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE);
    const b = hmacEvidenceFingerprint(DetectorSecret.new(KEY_B), VALUE);
    expect(a).not.toBe(b);
  });

  test("2a. the fingerprint is NOT the unkeyed SHA-256 of the input", () => {
    expect(hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE)).not.toBe(
      unkeyedDigestOracle(VALUE),
    );
  });

  test("2b. the fingerprint is NOT the empty-key HMAC of the input", () => {
    expect(hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE)).not.toBe(
      emptyKeyOracle(VALUE),
    );
  });

  test("2c. it IS exactly HMAC-SHA-256(key, value), per an independent implementation", () => {
    expect(hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE)).toBe(
      keyedOracle(KEY_A, VALUE),
    );
    expect(hmacEvidenceFingerprint(DetectorSecret.new(KEY_B), VALUE)).toBe(
      keyedOracle(KEY_B, VALUE),
    );
  });

  test("3. same key ⇒ stable fingerprint; and it still varies with the input", () => {
    const first = hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE);
    const second = hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), VALUE);
    expect(first).toBe(second);
    expect(hmacEvidenceFingerprint(DetectorSecret.new(KEY_A), "c@d.com")).not.toBe(first);
  });
});

/* ==========================================================================
 * SITE 2 — `DeterministicDetector#hmacFingerprint` (deterministic.ts), reached
 * only through `evaluate()`, i.e. exactly the way production reaches it.
 * ========================================================================== */

const OPENAI_KEY = `sk-${"abcdefghijklmnopqrstuvwxyz012345"}`; // sk- + 32 alnum

function secretDetector(key: string): DeterministicDetector {
  return DeterministicDetector.new({
    id: "secrets",
    supported_sources: ["user"],
    keywords: [],
    regex: [],
    secret_patterns: ["open_ai_api_key"],
    fingerprint_key: DetectorSecret.new(key),
  });
}

function promptInput(content: string): DetectorInput {
  const env = normalizeRequest("chat_completions", { messages: [{ role: "user", content }] });
  return {
    protocol: env.protocol,
    stage: env.stage,
    tenant: { organization_id: "org" },
    text: "",
    segments: env.segments,
  };
}

async function secretFingerprint(key: string, content: string): Promise<string> {
  const result = await secretDetector(key).evaluate(promptInput(content), DEADLINE());
  const finding = result.findings.find((f) => f.category === "secret.openai_api_key");
  expect(finding, "the detector must have produced a secret finding to fingerprint").toBeDefined();
  const fingerprint = finding?.fingerprint;
  expect(typeof fingerprint).toBe("string");
  return fingerprint as string;
}

describe("SITE 2 DeterministicDetector — per-finding evidence fingerprints", () => {
  const CONTENT = `please rotate ${OPENAI_KEY} today`;

  test("1. two detectors with DIFFERENT keys fingerprint the SAME secret differently", async () => {
    const a = await secretFingerprint(KEY_A, CONTENT);
    const b = await secretFingerprint(KEY_B, CONTENT);
    expect(a).toMatch(SHAPE);
    expect(b).toMatch(SHAPE);
    expect(a).not.toBe(b);
  });

  test("2a. the fingerprint is NOT the unkeyed SHA-256 of the matched secret", async () => {
    expect(await secretFingerprint(KEY_A, CONTENT)).not.toBe(unkeyedDigestOracle(OPENAI_KEY));
  });

  test("2b. the fingerprint is NOT the empty-key HMAC of the matched secret", async () => {
    expect(await secretFingerprint(KEY_A, CONTENT)).not.toBe(emptyKeyOracle(OPENAI_KEY));
  });

  test("2c. it IS exactly HMAC-SHA-256(configured key, matched secret)", async () => {
    expect(await secretFingerprint(KEY_A, CONTENT)).toBe(keyedOracle(KEY_A, OPENAI_KEY));
    expect(await secretFingerprint(KEY_B, CONTENT)).toBe(keyedOracle(KEY_B, OPENAI_KEY));
  });

  test("3. same key ⇒ same fingerprint across instances, evaluations and surrounding text", async () => {
    const first = await secretFingerprint(KEY_A, CONTENT);
    const second = await secretFingerprint(KEY_A, CONTENT);
    const elsewhere = await secretFingerprint(KEY_A, `different prose entirely ${OPENAI_KEY}`);
    expect(second).toBe(first);
    // Correlatable: the same secret in a different message is the same evidence id.
    expect(elsewhere).toBe(first);
  });

  test("3b. a different secret under the same key is a different fingerprint", async () => {
    const other = `sk-${"zyxwvutsrqponmlkjihgfedcba543210"}`;
    const a = await secretFingerprint(KEY_A, CONTENT);
    const b = await secretFingerprint(KEY_A, `leak ${other}`);
    expect(b).not.toBe(a);
    expect(b).toBe(keyedOracle(KEY_A, other));
  });

  test("no key configured ⇒ fingerprint is null, NEVER an unkeyed digest", async () => {
    // Keyword detectors may legally omit the key (only `secret_patterns`
    // requires it). Rust returns `None` rather than degrading to a plain hash.
    const detector = DeterministicDetector.new({
      id: "kw",
      supported_sources: ["user"],
      keywords: ["classified"],
      regex: [],
      secret_patterns: [],
    });
    const result = await detector.evaluate(promptInput("this is classified material"), DEADLINE());
    const finding = result.findings.find((f) => f.category === "contains");
    expect(finding).toBeDefined();
    expect(finding?.fingerprint).toBeNull();
    expect(finding?.fingerprint).not.toBe(unkeyedDigestOracle("classified"));
  });
});

/* ==========================================================================
 * SITE 3 — the three adapters, end to end through `evaluate()`.
 * ========================================================================== */

const PROBE = "sentinel-payload-9f3a";

function llamaConfig(key: string): WorkersAiLlamaGuardConfig {
  return {
    id: "llama",
    model: WORKERS_AI_LLAMA_GUARD_DEFAULT_MODEL,
    timeoutMs: 2_000,
    maxPayloadBytes: 1_000_000,
    supportedSources: ["user"],
    fingerprintKey: DetectorSecret.new(key),
  };
}

const unsafeWorkersAi: WorkersAiClient = {
  async run(): Promise<unknown> {
    return { response: "unsafe\nS2" };
  },
};

async function llamaFingerprint(key: string): Promise<string> {
  const detector = WorkersAiLlamaGuardDetector.withWorkersAi(llamaConfig(key), unsafeWorkersAi);
  const result = await detector.evaluate(userInput(PROBE), DEADLINE());
  return result.findings[0]?.fingerprint as string;
}

function llmGuardConfig(key: string): LlmGuardPromptInjectionConfig {
  return {
    id: "llm-guard",
    endpoint: "https://guard.example.com/analyze/prompt",
    scoreThresholdPercent: 50,
    timeoutMs: 2_000,
    maxPayloadBytes: 1_000_000,
    maxResponseBytes: 1_000_000,
    allowPrivateNetwork: false,
    supportedSources: ["user"],
    fingerprintKey: DetectorSecret.new(key),
  };
}

async function llmGuardFingerprint(key: string): Promise<string> {
  const transport = FixtureTransport.fromRecorded({
    exchanges: [
      {
        request: { prompt: PROBE },
        response: { status: 200, body: { is_valid: false, scanners: { PromptInjection: 0.95 } } },
      },
    ],
  });
  const detector = LlmGuardPromptInjectionDetector.withTransport(llmGuardConfig(key), transport);
  const result = await detector.evaluate(userInput(PROBE), DEADLINE());
  return result.findings[0]?.fingerprint as string;
}

const EMAIL = "a@b.com";
const EMAIL_PROMPT = "my email is a@b.com";

function presidioConfig(key: string): PresidioDetectorConfig {
  return {
    id: "presidio",
    endpoint: "https://presidio.example.com/analyze",
    language: "en",
    scoreThresholdPercent: 50,
    timeoutMs: 2_000,
    maxPayloadBytes: 1_000_000,
    maxResponseBytes: 1_000_000,
    allowPrivateNetwork: false,
    supportedSources: ["user"],
    fingerprintKey: DetectorSecret.new(key),
  };
}

async function presidioFingerprint(key: string): Promise<string> {
  const transport = FixtureTransport.fromRecorded({
    exchanges: [
      {
        request: { text: EMAIL_PROMPT, language: "en", score_threshold: 0.5 },
        response: {
          status: 200,
          body: [{ entity_type: "EMAIL_ADDRESS", start: 12, end: 19, score: 0.9 }],
        },
      },
    ],
  });
  const detector = PresidioDetector.withTransport(presidioConfig(key), transport);
  const result = await detector.evaluate(userInput(EMAIL_PROMPT), DEADLINE());
  return result.findings[0]?.fingerprint as string;
}

describe.each([
  ["WorkersAiLlamaGuardDetector", (k: string) => llamaFingerprint(k), PROBE],
  ["LlmGuardPromptInjectionDetector", (k: string) => llmGuardFingerprint(k), PROBE],
  ["PresidioDetector", (k: string) => presidioFingerprint(k), EMAIL],
] as const)(
  "SITE 3 %s — evidence fingerprints are keyed",
  (_name, fingerprintOf, fingerprinted) => {
    test("1. different keys ⇒ different fingerprints for the same input", async () => {
      const a = await fingerprintOf(KEY_A);
      const b = await fingerprintOf(KEY_B);
      expect(a).toMatch(SHAPE);
      expect(b).toMatch(SHAPE);
      expect(a).not.toBe(b);
    });

    test("2a. NOT the unkeyed SHA-256 of the fingerprinted value", async () => {
      expect(await fingerprintOf(KEY_A)).not.toBe(unkeyedDigestOracle(fingerprinted));
    });

    test("2b. NOT the empty-key HMAC of the fingerprinted value", async () => {
      expect(await fingerprintOf(KEY_A)).not.toBe(emptyKeyOracle(fingerprinted));
    });

    test("2c. IS exactly HMAC-SHA-256(configured key, fingerprinted value)", async () => {
      expect(await fingerprintOf(KEY_A)).toBe(keyedOracle(KEY_A, fingerprinted));
      expect(await fingerprintOf(KEY_B)).toBe(keyedOracle(KEY_B, fingerprinted));
    });

    test("3. same key ⇒ stable fingerprint across evaluations", async () => {
      expect(await fingerprintOf(KEY_A)).toBe(await fingerprintOf(KEY_A));
    });
  },
);

/* ==========================================================================
 * 4. EVIDENCE IS NOT PERSISTED.
 * ========================================================================== */

describe("4. evidence is not persisted — the fingerprint is the ONLY record", () => {
  test("DeterministicDetector: matched_text null, raw secret and key absent from the result", async () => {
    const content = `please rotate ${OPENAI_KEY} today`;
    const result = await secretDetector(KEY_A).evaluate(promptInput(content), DEADLINE());
    const serialized = JSON.stringify(result);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.matched_text).toBeNull();
      expect(finding.attributes).toEqual({});
    }
    expect(serialized).not.toContain(OPENAI_KEY);
    // Not even a fragment: the distinctive tail of the secret must be gone too.
    expect(serialized).not.toContain("abcdefghijklmnopqrstuvwxyz012345");
    expect(serialized).not.toContain(KEY_A);
  });

  test("adapters: matched_text null and the probe value absent from every result", async () => {
    const llama = await WorkersAiLlamaGuardDetector.withWorkersAi(
      llamaConfig(KEY_A),
      unsafeWorkersAi,
    ).evaluate(userInput(PROBE), DEADLINE());
    for (const finding of llama.findings) {
      expect(finding.matched_text).toBeNull();
    }
    expect(JSON.stringify(llama)).not.toContain(PROBE);
    expect(JSON.stringify(llama)).not.toContain(KEY_A);
  });

  test("the configured key never serializes: DetectorSecret redacts under JSON/String", () => {
    const secret = DetectorSecret.new(KEY_A);
    expect(JSON.stringify({ fingerprintKey: secret })).not.toContain(KEY_A);
    expect(String(secret)).not.toContain(KEY_A);
    expect(`${secret}`).toBe("<redacted>");
  });

  test("a redaction patch carries the replacement, never the value it replaced", async () => {
    const content = `please rotate ${OPENAI_KEY} today`;
    const result = await secretDetector(KEY_A).evaluate(promptInput(content), DEADLINE());
    expect(result.patches.length).toBeGreaterThan(0);
    for (const patch of result.patches) {
      expect(patch.replacement).toBe("[REDACTED]");
      expect(JSON.stringify(patch)).not.toContain(OPENAI_KEY);
    }
  });
});
