import { describe, expect, test } from "vitest";

import {
  CanonicalAiRequest,
  ModelRegistry,
  ModelRegistryError,
  chatCompletionToMessage,
  finishReasonToStopReason,
  modelRouteWithRouting,
  newModelRegistryEntry,
  toChatCompletions,
} from "../src/index.js";

describe("ModelRegistry", () => {
  test("resolves an enabled model to its primary route", () => {
    const registry = ModelRegistry.create([
      newModelRegistryEntry("fast-chat", "openai", "gpt-4o-mini"),
    ]);
    const resolved = registry.resolve("fast-chat");
    expect(resolved.logicalModel).toBe("fast-chat");
    expect(resolved.primary.provider).toBe("openai");
    expect(resolved.primary.providerModel).toBe("gpt-4o-mini");
  });

  test("rejects duplicate names at construction (edge case)", () => {
    try {
      ModelRegistry.create([
        newModelRegistryEntry("fast-chat", "openai", "a"),
        newModelRegistryEntry("fast-chat", "anthropic", "b"),
      ]);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(ModelRegistryError);
      expect((error as ModelRegistryError).kind).toBe("DuplicateModel");
      expect((error as ModelRegistryError).modelName).toBe("fast-chat");
    }
  });

  test("rejects a disabled model at resolution time", () => {
    const entry = newModelRegistryEntry("fast-chat", "openai", "gpt-4o-mini");
    entry.enabled = false;
    const registry = ModelRegistry.create([entry]);
    expect(() => registry.resolve("fast-chat")).toThrowError(ModelRegistryError);
  });

  test("sorts fallbacks by priority → weight(desc) → provider → model", () => {
    const entry = newModelRegistryEntry("fast-chat", "openai", "gpt-4o-mini");
    entry.fallbacks = [
      modelRouteWithRouting("gemini", "gemini-2.5-flash", undefined, undefined, 20, 10),
      modelRouteWithRouting("anthropic", "claude-3-5-sonnet-latest", undefined, undefined, 10, 1),
      modelRouteWithRouting("grok", "grok-4.20-fast", undefined, undefined, 20, 20),
    ];
    const registry = ModelRegistry.create([entry]);
    expect(registry.resolve("fast-chat").fallbacks.map((r) => r.provider)).toEqual([
      "anthropic",
      "grok",
      "gemini",
    ]);
  });

  test("enabledModels lists enabled entries sorted by name", () => {
    const disabled = newModelRegistryEntry("z-disabled", "openai", "m");
    disabled.enabled = false;
    const registry = ModelRegistry.create([
      newModelRegistryEntry("b-model", "openai", "m"),
      newModelRegistryEntry("a-model", "openai", "m"),
      disabled,
    ]);
    expect(registry.enabledModels().map((e) => e.name)).toEqual(["a-model", "b-model"]);
  });
});

describe("CanonicalAiRequest (/v1/responses)", () => {
  test("canonicalizes a simple string input with instructions + max_output_tokens", () => {
    const body = CanonicalAiRequest.fromResponsesBody({
      model: "logical",
      instructions: "be concise",
      input: "hello",
      max_output_tokens: 64,
    }).intoChatBodyWithSystemField() as any;
    expect(body.messages[0].role).toBe("user");
    expect(body.messages[0].content).toBe("hello");
    expect(body.system).toBe("be concise");
    expect(body.max_tokens).toBe(64);
  });

  test("parses tool definitions, tool_choice, and multimodal input", () => {
    const body = CanonicalAiRequest.fromResponsesBody({
      instructions: "be concise",
      tools: [
        {
          type: "function",
          function: { name: "lookup_weather", parameters: { type: "object" } },
        },
      ],
      tool_choice: { type: "tool", name: "lookup_weather" },
      input: [
        {
          role: "user",
          content: [
            { type: "input_text", text: "hello" },
            { type: "input_image", image_url: "https://example.com/a.png" },
            { type: "input_image", image_url: "data:image/png;base64,Zm9v" },
          ],
        },
      ],
    }).intoChatBodyWithSystemField() as any;
    expect(body.tools[0].function.name).toBe("lookup_weather");
    expect(body.tool_choice.type).toBe("function");
    expect(body.messages[0].content[1].image_url.url).toBe("https://example.com/a.png");
    expect(body.messages[0].content[2].image_url.url).toBe("data:image/png;base64,Zm9v");
  });

  test("rejects mixed tool-call + text content (edge case)", () => {
    expect(() =>
      CanonicalAiRequest.fromResponsesBody({
        input: [
          {
            role: "assistant",
            content: [
              { type: "text", text: "hello" },
              { type: "tool_call", id: "call_1", name: "w", arguments: {} },
            ],
          },
        ],
      }),
    ).toThrowError(/text, image, and tool-call input content only/);
  });

  test("emits a Gemini body (contents/systemInstruction/generationConfig)", () => {
    const body = CanonicalAiRequest.fromResponsesBody({
      instructions: "be concise",
      input: [{ type: "input_text", text: "hello" }],
      max_output_tokens: 64,
    }).intoGeminiBody() as any;
    expect(body.systemInstruction.parts[0].text).toBe("be concise");
    expect(body.contents[0].parts[0].text).toBe("hello");
    expect(body.generationConfig.maxOutputTokens).toBe(64);
  });
});

describe("Anthropic Messages ⇄ OpenAI translation (issue #272)", () => {
  test("translates system + sampling params + stop_sequences", () => {
    const chat = toChatCompletions({
      model: "claude-logical",
      max_tokens: 256,
      temperature: 0.5,
      stop_sequences: ["STOP"],
      stream: true,
      system: "be concise",
      messages: [{ role: "user", content: "hello" }],
    }) as any;
    expect(chat.stop[0]).toBe("STOP");
    expect(chat.messages[0].role).toBe("system");
    expect(chat.messages[0].content).toBe("be concise");
    expect(chat.messages[1].content).toBe("hello");
  });

  test("translates tool_use → tool_calls and tool_result → tool message", () => {
    const chat = toChatCompletions({
      model: "claude-logical",
      max_tokens: 512,
      tools: [{ name: "lookup_weather", input_schema: { type: "object" } }],
      tool_choice: { type: "tool", name: "lookup_weather" },
      messages: [
        { role: "user", content: "weather?" },
        {
          role: "assistant",
          content: [
            { type: "text", text: "checking" },
            {
              type: "tool_use",
              id: "toolu_1",
              name: "lookup_weather",
              input: { city: "Shanghai" },
            },
          ],
        },
        {
          role: "user",
          content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "21C" }],
        },
      ],
    }) as any;
    expect(chat.tools[0].function.name).toBe("lookup_weather");
    expect(chat.tool_choice.function.name).toBe("lookup_weather");
    const assistant = chat.messages[1];
    expect(assistant.content).toBe("checking");
    expect(assistant.tool_calls[0].function.arguments).toBe('{"city":"Shanghai"}');
    expect(chat.messages[2].role).toBe("tool");
    expect(chat.messages[2].content).toBe("21C");
  });

  test("base64 image blocks become data URLs", () => {
    const chat = toChatCompletions({
      model: "m",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "what is this" },
            { type: "image", source: { type: "base64", media_type: "image/png", data: "Zm9v" } },
          ],
        },
      ],
    }) as any;
    expect(chat.messages[0].content[1].image_url.url).toBe("data:image/png;base64,Zm9v");
  });

  test("chat completion → Anthropic message (id + stop_reason + usage)", () => {
    const message = chatCompletionToMessage(
      {
        id: "chatcmpl-abc",
        model: "gpt-4o",
        choices: [
          {
            message: {
              role: "assistant",
              content: "hello there",
              tool_calls: [
                {
                  id: "call_1",
                  type: "function",
                  function: { name: "lookup", arguments: '{"q":"x"}' },
                },
              ],
            },
            finish_reason: "tool_calls",
          },
        ],
        usage: { prompt_tokens: 12, completion_tokens: 7 },
      },
      "claude-logical",
    ) as any;
    expect(message.id).toBe("msg-abc");
    expect(message.content[0].text).toBe("hello there");
    expect(message.content[1].type).toBe("tool_use");
    expect(message.content[1].input.q).toBe("x");
    expect(message.stop_reason).toBe("tool_use");
    expect(message.usage.input_tokens).toBe(12);
  });

  test("an already-Anthropic-shaped response passes through unchanged (edge case)", () => {
    const native = {
      id: "msg_native",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: "native" }],
      stop_reason: "end_turn",
      usage: { input_tokens: 1, output_tokens: 2 },
    };
    expect(chatCompletionToMessage(native, "claude-logical")).toEqual(native);
  });

  test("finishReasonToStopReason maps the OpenAI vocabulary", () => {
    expect(finishReasonToStopReason("length", false)).toBe("max_tokens");
    expect(finishReasonToStopReason("stop", false)).toBe("end_turn");
    expect(finishReasonToStopReason("stop", true)).toBe("tool_use");
  });
});
