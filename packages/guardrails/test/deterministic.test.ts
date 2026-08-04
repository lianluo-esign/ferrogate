import { describe, expect, test } from "vitest";
import {
  DetectorError,
  type DetectorInput,
  DetectorSecret,
  DeterministicDetector,
  MAX_FINDINGS_PER_EVALUATION,
  normalizeRequest,
} from "../src/index.js";

const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"; // valid AKIA + 16 chars
const DEADLINE = () => Date.now() + 5_000;

function inputFrom(body: unknown): DetectorInput {
  const env = normalizeRequest("chat_completions", body);
  return {
    protocol: env.protocol,
    stage: env.stage,
    tenant: { organization_id: "org" },
    text: "",
    segments: env.segments,
  };
}

describe("DeterministicDetector secret scanning", () => {
  const detector = DeterministicDetector.new({
    id: "secrets",
    supported_sources: ["user"],
    keywords: [],
    regex: [],
    secret_patterns: ["aws_access_key_id"],
    fingerprint_key: DetectorSecret.new("evidence-key"),
  });

  test("fails on a leaked key with sanitized evidence + redaction patch", async () => {
    const input = inputFrom({ messages: [{ role: "user", content: `deploy ${AWS_KEY} now` }] });
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.verdict).toBe("fail");
    const finding = result.findings.find((f) => f.category === "secret.aws_access_key_id");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(finding?.fingerprint).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(finding?.matched_text).toBeNull();
    expect(result.patches).toHaveLength(1);
    expect(result.patches[0]?.replacement).toBe("[REDACTED]");
    // The raw secret must never appear in serialized evidence.
    expect(JSON.stringify(result)).not.toContain(AWS_KEY);
  });

  test("passes on benign content", async () => {
    const input = inputFrom({ messages: [{ role: "user", content: "hello there" }] });
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.verdict).toBe("pass");
    expect(result.findings).toHaveLength(0);
  });

  test("expired deadline yields timeout", async () => {
    const input = inputFrom({ messages: [{ role: "user", content: "x" }] });
    await expect(detector.evaluate(input, Date.now() - 1)).rejects.toMatchObject({
      kind: "timeout",
    });
  });
});

describe("coalesced + per-segment scanning", () => {
  test("keyword split across adjacent same-source segments is caught (coalesced)", async () => {
    const detector = DeterministicDetector.new({
      id: "kw",
      supported_sources: ["user"],
      keywords: ["forbidden"],
      regex: [],
      secret_patterns: [],
    });
    const input = inputFrom({
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "for" },
            { type: "text", text: "bidden" },
          ],
        },
      ],
    });
    expect(input.segments.length).toBe(2);
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.verdict).toBe("fail");
    expect(result.findings.some((f) => f.category === "contains")).toBe(true);
  });

  test("per-segment anchor context catches a boundary-anchored secret the coalesced scan hides", async () => {
    const detector = DeterministicDetector.new({
      id: "aws",
      supported_sources: ["user"],
      keywords: [],
      regex: [],
      secret_patterns: ["aws_access_key_id"],
      fingerprint_key: DetectorSecret.new("k"),
    });
    // "mykey" ends in a word char, destroying the \b before AKIA once coalesced.
    const input = inputFrom({
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "mykey" },
            { type: "text", text: AWS_KEY },
          ],
        },
      ],
    });
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.findings.some((f) => f.category === "secret.aws_access_key_id")).toBe(true);
  });
});

describe("size + json + request constraints", () => {
  test("max_input_bytes overflow yields size.input_bytes", async () => {
    const detector = DeterministicDetector.new({
      id: "sz",
      supported_sources: ["user"],
      keywords: [],
      regex: [],
      secret_patterns: [],
      max_input_bytes: 3,
    });
    const input = inputFrom({ messages: [{ role: "user", content: "way too long" }] });
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.findings.some((f) => f.category === "size.input_bytes")).toBe(true);
  });

  test("json forbidden_key on a tool-arguments segment", async () => {
    const detector = DeterministicDetector.new({
      id: "json",
      supported_sources: ["tool_arguments"],
      keywords: [],
      regex: [],
      secret_patterns: [],
      json: { required_keys: [], forbidden_keys: ["/password"] },
    });
    const input = inputFrom({
      messages: [
        {
          role: "assistant",
          content: null,
          tool_calls: [{ function: { arguments: '{"password":"p"}' } }],
        },
      ],
    });
    const result = await detector.evaluate(input, DEADLINE());
    expect(result.findings.some((f) => f.category === "json.forbidden_key")).toBe(true);
  });

  test("request constraint denies a forbidden model", async () => {
    const detector = DeterministicDetector.new({
      id: "req",
      supported_sources: ["user"],
      keywords: [],
      regex: [],
      secret_patterns: [],
      request: {
        allowed_endpoints: [],
        allowed_models: [],
        forbidden_models: ["gpt-4o"],
        allowed_providers: [],
        forbidden_providers: [],
      },
    });
    const env = normalizeRequest("chat_completions", {
      messages: [{ role: "user", content: "hi" }],
    });
    const result = await detector.evaluate(
      {
        protocol: "chat_completions",
        stage: "request",
        tenant: {},
        model: "gpt-4o",
        text: "",
        segments: env.segments,
      },
      DEADLINE(),
    );
    expect(result.findings.some((f) => f.category === "request.model")).toBe(true);
  });
});

describe("config validation", () => {
  test("secret patterns without a fingerprint key are rejected", () => {
    expect(() =>
      DeterministicDetector.new({
        id: "bad",
        supported_sources: ["user"],
        keywords: [],
        regex: [],
        secret_patterns: ["aws_access_key_id"],
      }),
    ).toThrow(DetectorError);
  });

  test("no constraints at all is rejected", () => {
    expect(() =>
      DeterministicDetector.new({
        id: "empty",
        supported_sources: ["user"],
        keywords: [],
        regex: [],
        secret_patterns: [],
      }),
    ).toThrow(/at least one constraint/);
  });

  /**
   * Bounded evidence (`MAX_FINDINGS_PER_EVALUATION`). Two properties, both
   * load-bearing:
   *
   *  1. per-request memory is CAPPED regardless of input size — an unbounded
   *     findings array is an O(N) memory amplifier a repetitive flood can open;
   *  2. truncation FAILS CLOSED. The marker is a zero-width located finding at
   *     `[0, 0)`, which no positive-width patch can ever cover, so a downstream
   *     `has_unredactable_findings` check forces Deny. A truncated scan can
   *     never be fully scrubbed, so it must never be treated as scrubbable.
   *
   * The cap bounds memory, not the current quadratic CPU cost on repetitive
   * attacker-controlled input. Issue #817 tracks that production defect; a
   * longer test timeout here would only hide its signal.
   */
  test("bounded evidence: >10k matches emit one detector.truncated marker", async () => {
    const detector = DeterministicDetector.new({
      id: "flood",
      supported_sources: ["user"],
      keywords: ["x"],
      regex: [],
      secret_patterns: [],
    });
    const floods = MAX_FINDINGS_PER_EVALUATION + 500;
    const input = inputFrom({ messages: [{ role: "user", content: "x".repeat(floods) }] });
    const result = await detector.evaluate(input, Date.now() + 30_000);

    expect(result.verdict).toBe("fail");
    // Capped, not merely "large": cap + the one marker, never `floods`.
    expect(result.findings).toHaveLength(MAX_FINDINGS_PER_EVALUATION + 1);
    expect(result.findings.length).toBeLessThan(floods);

    // EXACTLY one marker, and it is the last finding.
    const markers = result.findings.filter((f) => f.category === "detector.truncated");
    expect(markers).toHaveLength(1);
    expect(result.findings.at(-1)?.category).toBe("detector.truncated");

    const marker = markers[0];
    expect(marker?.severity).toBe("critical");
    expect(marker?.confidence).toBe(1.0);
    // Zero-width and LOCATED: it names a segment (so it is not a global
    // annotation a redactor may ignore) but spans nothing (so nothing can
    // cover it).
    expect(marker?.byte_start).toBe(0);
    expect(marker?.byte_end).toBe(0);
    expect(marker?.segment_id).not.toBeNull();

    // The fail-closed property, asserted with the EXACT downstream predicate
    // (`state_quota_and_policy.rs`'s `has_unredactable_findings`): a patch
    // covers a located finding when
    //   patch.segment_id === finding.segment_id
    //     && patch.byte_start < finding.byte_end
    //     && finding.byte_start < patch.byte_end
    // For a zero-width finding at [0, 0) the first clause needs
    // `patch.byte_start < 0`, which no real byte offset can be. So the marker
    // is unredactable BY CONSTRUCTION, and a Redact action must escalate to
    // Deny — even though the flood's own matches are all patched.
    const covers = (p: (typeof result.patches)[number]): boolean =>
      p.segment_id === marker?.segment_id &&
      p.byte_start < (marker?.byte_end as number) &&
      (marker?.byte_start as number) < p.byte_end;
    expect(result.patches.filter(covers)).toHaveLength(0);
    // Sanity: the predicate is not vacuously false — it DOES cover an ordinary
    // positive-width finding in the same segment.
    const ordinary = result.findings.find((f) => f.category === "contains");
    expect(
      result.patches.some(
        (p) =>
          p.segment_id === ordinary?.segment_id &&
          p.byte_start < (ordinary?.byte_end as number) &&
          (ordinary?.byte_start as number) < p.byte_end,
      ),
    ).toBe(true);
  });

  test("under the cap, no truncation marker is emitted", async () => {
    // The other half: the cap must not fire on ordinary traffic, or every
    // request would fail closed.
    const detector = DeterministicDetector.new({
      id: "flood",
      supported_sources: ["user"],
      keywords: ["x"],
      regex: [],
      secret_patterns: [],
    });
    const input = inputFrom({ messages: [{ role: "user", content: "x".repeat(10) }] });
    const result = await detector.evaluate(input, Date.now() + 30_000);
    expect(result.findings.some((f) => f.category === "detector.truncated")).toBe(false);
    expect(result.findings).toHaveLength(10);
  });
});
