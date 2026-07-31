import { describe, expect, test } from "vitest";
import {
  applyContentPatchesToDocument,
  contentFingerprint,
  normalizeRequest,
  normalizeResponse,
  parseProtocolPath,
  validateContentPatchPermissions,
  validateContentPatchesForSegments,
  type ContentPatch,
} from "../src/index.js";

describe("normalizeRequest (chat)", () => {
  test("walks messages, tool_calls, tools, metadata into segments", () => {
    const env = normalizeRequest("chat_completions", {
      messages: [
        { role: "system", content: "be nice" },
        { role: "user", content: "hello" },
        {
          role: "assistant",
          content: null,
          tool_calls: [{ function: { arguments: '{"q":"x"}' } }],
        },
      ],
      tools: [{ name: "search" }],
      metadata: { tenant: "acme" },
    });
    const sources = env.segments.map((s) => s.source);
    expect(sources).toContain("system");
    expect(sources).toContain("user");
    expect(sources).toContain("tool_arguments");
    expect(sources).toContain("tool_schema");
    expect(sources).toContain("metadata");
    // fingerprint format
    expect(env.segments[0]?.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("normalizeResponse (chat SSE)", () => {
  test("accumulates delta content across frames", () => {
    const sse = [
      'data: {"choices":[{"delta":{"content":"Hel"}}]}',
      "",
      'data: {"choices":[{"delta":{"content":"lo"}}]}',
      "",
      "data: [DONE]",
      "",
    ].join("\n");
    const env = normalizeResponse("chat_completions", new TextEncoder().encode(sse), true);
    expect(env.segments).toHaveLength(1);
    expect(env.segments[0]?.text).toBe("Hello");
    expect(env.segments[0]?.source).toBe("assistant");
  });

  test("embeddings response is never normalized", () => {
    const env = normalizeResponse("embeddings", new TextEncoder().encode('{"x":1}'), false);
    expect(env.segments).toHaveLength(0);
  });
});

describe("content patches", () => {
  const doc = { messages: [{ role: "user", content: "leak AKIA1234 here" }] };
  const env = normalizeRequest("chat_completions", doc);
  const segment = env.segments[0]!;
  const start = 5; // byte offset of AKIA...
  const end = 13;

  const patch: ContentPatch = {
    segment_id: segment.segment_id,
    expected_fingerprint: segment.fingerprint,
    protocol_location: segment.protocol_location,
    byte_start: start,
    byte_end: end,
    replacement: "[REDACTED]",
  };

  test("valid patch validates and applies", () => {
    expect(() => validateContentPatchesForSegments(env.segments, [patch])).not.toThrow();
    const out = applyContentPatchesToDocument(doc, env, ["user"], [patch]) as typeof doc;
    expect(out.messages[0]?.content).toBe("leak [REDACTED] here");
    // input document not mutated
    expect(doc.messages[0]?.content).toBe("leak AKIA1234 here");
  });

  test("stale fingerprint is rejected", () => {
    const stale = { ...patch, expected_fingerprint: "sha256:deadbeef" };
    expect(() => validateContentPatchesForSegments(env.segments, [stale])).toThrow(/stale/i);
  });

  test("overlapping range is rejected", () => {
    const a: ContentPatch = { ...patch, byte_start: 0, byte_end: 6 };
    const b: ContentPatch = { ...patch, byte_start: 4, byte_end: 10 };
    expect(() => validateContentPatchesForSegments(env.segments, [a, b])).toThrow(/overlapping/i);
  });

  test("immutable JSON source is a protected path", () => {
    const jsonDoc = { messages: [{ role: "user", content: "hi" }], metadata: { k: "v" } };
    const jsonEnv = normalizeRequest("chat_completions", jsonDoc);
    const metaSeg = jsonEnv.segments.find((s) => s.source === "metadata")!;
    const metaPatch: ContentPatch = {
      segment_id: metaSeg.segment_id,
      expected_fingerprint: metaSeg.fingerprint,
      protocol_location: metaSeg.protocol_location,
      byte_start: 0,
      byte_end: 1,
      replacement: "x",
    };
    expect(() => validateContentPatchPermissions(jsonEnv, ["metadata"], [metaPatch])).toThrow(
      /protected/i,
    );
  });
});

describe("parseProtocolPath", () => {
  test("valid dotted/indexed path", () => {
    expect(parseProtocolPath("messages[0].content")).toEqual([
      { kind: "field", value: "messages" },
      { kind: "index", value: 0 },
      { kind: "field", value: "content" },
    ]);
  });

  test("rejects traversal and leading dot", () => {
    expect(parseProtocolPath("..")).toBeUndefined();
    expect(parseProtocolPath(".foo")).toBeUndefined();
    expect(parseProtocolPath("")).toBeUndefined();
  });
});

describe("contentFingerprint", () => {
  test("stable sha256 prefix", () => {
    expect(contentFingerprint("abc")).toBe(
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});
