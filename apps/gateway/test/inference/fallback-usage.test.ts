/**
 * The buffered no-usage harvesters (`src/inference/fallback-usage.ts`, #976
 * Phase B1). These are the pure functions the three buffered record sites call
 * when a valid 2xx body carried no usage object; the money-path wiring is
 * exercised end-to-end in `usage-fallback.test.ts`.
 *
 * The text-extraction assertions are tokenizer-independent (string equality on
 * the harvested text), so they pin the DIALECT logic — which bytes each family's
 * completion lives in, and which request knobs are excluded from the prompt —
 * without coupling to the encoding.
 */
import { describe, expect, it } from "vitest";

import {
  completionTextFrom,
  localFallbackUsage,
  promptTextFrom,
} from "../../src/inference/fallback-usage.js";

describe("promptTextFrom", () => {
  it("collects string leaves under structural keys, in order", () => {
    expect(
      promptTextFrom({ messages: [{ role: "user", content: "hello world" }] }),
    ).toBe("user\nhello world");
  });

  it("excludes non-prompt knobs so a long id or seed cannot inflate the count", () => {
    // model / seed / user / max_tokens / temperature are knobs, not prompt.
    expect(
      promptTextFrom({
        model: "gpt-4o",
        seed: "a-very-long-seed-value",
        user: "tenant-9a03494f-user-01",
        max_tokens: 4096,
        temperature: 0.7,
        messages: [{ role: "user", content: "hi" }],
      }),
    ).toBe("user\nhi");
  });

  it("drops the Anthropic content-block `type` discriminator", () => {
    expect(
      promptTextFrom({ messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }] }),
    ).toBe("user\nhi");
  });

  it("walks Gemini `contents`/`parts` the same as any other ingress shape", () => {
    expect(
      promptTextFrom({ contents: [{ role: "user", parts: [{ text: "hi there" }] }] }),
    ).toBe("user\nhi there");
  });

  it("is empty on a request with no text", () => {
    expect(promptTextFrom({ model: "gpt-4o", max_tokens: 10 })).toBe("");
  });
});

describe("completionTextFrom", () => {
  it("openai: reads choices[].message.content (bare string)", () => {
    expect(
      completionTextFrom("openai", { choices: [{ message: { content: "hello world" } }] }),
    ).toBe("hello world");
  });

  it("openai: reads content PARTS and Responses output[].content[].text", () => {
    expect(
      completionTextFrom("openai", {
        choices: [{ message: { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] } }],
      }),
    ).toBe("a\nb");
    expect(
      completionTextFrom("openai", {
        output: [{ content: [{ type: "output_text", text: "resp" }] }],
      }),
    ).toBe("resp");
  });

  it("anthropic: reads content[].text and ignores non-text blocks", () => {
    expect(
      completionTextFrom("anthropic", {
        content: [
          { type: "text", text: "foo" },
          { type: "tool_use", id: "t1", name: "x", input: {} },
        ],
      }),
    ).toBe("foo");
  });

  it("gemini: reads candidates[].content.parts[].text", () => {
    expect(
      completionTextFrom("gemini", {
        candidates: [{ content: { role: "model", parts: [{ text: "g1" }, { text: "g2" }] } }],
      }),
    ).toBe("g1\ng2");
  });

  it("bedrock: reads output.message.content[].text (Converse)", () => {
    expect(
      completionTextFrom("bedrock", {
        output: { message: { role: "assistant", content: [{ text: "b1" }] } },
      }),
    ).toBe("b1");
  });

  it("is empty when the dialect-correct location holds no text", () => {
    expect(completionTextFrom("openai", { choices: [] })).toBe("");
    expect(completionTextFrom("anthropic", {})).toBe("");
  });
});

describe("localFallbackUsage", () => {
  it("counts both sides and sums the total", () => {
    // "hello world" → 2 tokens on o200k_base, both sides.
    expect(
      localFallbackUsage(
        { messages: [{ content: "hello world" }] },
        { choices: [{ message: { content: "hello world" } }] },
        "openai",
        "gpt-4o",
      ),
    ).toEqual({ promptTokens: 2, completionTokens: 2, totalTokens: 4 });
  });

  it("returns a prompt-only count when the completion side is empty", () => {
    expect(
      localFallbackUsage({ messages: [{ content: "hello world" }] }, {}, "openai", "gpt-4o"),
    ).toEqual({ promptTokens: 2, completionTokens: 0, totalTokens: 2 });
  });

  it("returns undefined when NEITHER side yields text — never invents a floor", () => {
    expect(localFallbackUsage({}, {}, "openai", "gpt-4o")).toBeUndefined();
    expect(
      localFallbackUsage({ model: "gpt-4o", max_tokens: 8 }, { choices: [] }, "openai", "gpt-4o"),
    ).toBeUndefined();
  });
});
