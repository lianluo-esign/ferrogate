/**
 * The OFFICIAL `@anthropic-ai/sdk` client against FerroGate's `/v1/messages`.
 *
 * Two upstream dialects are exercised, because they are two different code
 * paths inside the gateway and only one of them is a relay:
 *
 *  - `claude-3-5-sonnet-20241022` → an ANTHROPIC upstream, i.e. Anthropic in,
 *    Anthropic out;
 *  - `claude-on-openai` → an OPENAI upstream, i.e. the request is translated to
 *    chat-completions on the way in and the completion is translated back to an
 *    Anthropic `Message` on the way out
 *    (`apps/gateway/src/inference/anthropic.ts`,
 *    `apps/gateway/src/streaming/anthropic.ts`).
 *
 * The second is the interesting one for adoption: it is the claim that an
 * Anthropic-SDK codebase can be pointed at FerroGate and served by ANY provider
 * behind it. If the translated frames were slightly wrong, `messages.stream()`
 * — which accumulates `message_start` / `content_block_delta` / `message_delta`
 * into a `Message` and throws on an inconsistent sequence — would say so.
 */
import { APIError, AuthenticationError, PermissionDeniedError } from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import {
  DONE_FRAME,
  anthropicClient,
  dataFrame,
  interceptUpstream,
  upstreamJson,
  upstreamSse,
} from "./harness.js";

const ANTHROPIC_MESSAGE = {
  id: "msg_conformance",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "hello from claude" }],
  stop_reason: "end_turn",
  stop_sequence: null,
  usage: { input_tokens: 12, output_tokens: 5 },
};

const OPENAI_COMPLETION = {
  id: "chatcmpl-anthropic-leg",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "hello from an openai upstream" },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 7, completion_tokens: 6, total_tokens: 13 },
};

const CHUNK_BASE = {
  id: "chatcmpl-anthropic-stream",
  object: "chat.completion.chunk",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
};

const OPENAI_STREAM = [
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { role: "assistant", content: "Fer" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { content: "ro" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { content: "Gate" } }] }),
  dataFrame({
    ...CHUNK_BASE,
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    usage: { prompt_tokens: 4, completion_tokens: 3, total_tokens: 7 },
  }),
  DONE_FRAME,
];

/** Run `body` and return the error it threw. */
async function captured(body: () => Promise<unknown>): Promise<APIError> {
  try {
    await body();
  } catch (error) {
    if (error instanceof APIError) return error;
    throw error;
  }
  throw new Error("expected the SDK to throw an APIError");
}

describe("@anthropic-ai/sdk — messages", () => {
  it("round-trips against an Anthropic upstream", async () => {
    const upstream = interceptUpstream(() => upstreamJson(ANTHROPIC_MESSAGE));
    try {
      const message = await anthropicClient().messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 64,
        system: "be brief",
        messages: [{ role: "user", content: "hi" }],
      });

      // Read through the SDK's own content-block union.
      const block = message.content[0];
      expect(block?.type).toBe("text");
      if (block?.type !== "text") throw new Error("expected a text block");
      expect(block.text).toBe("hello from claude");
      expect(message.stop_reason).toBe("end_turn");
      expect(message.usage.input_tokens).toBe(12);

      // The upstream saw an Anthropic-shaped body with the gateway's own
      // credential in `x-api-key` and the pinned `anthropic-version`.
      const call = upstream.last();
      expect(call.url).toBe("https://api.anthropic.conformance.test/v1/messages");
      expect(call.headers["anthropic-version"]).toBe("2023-06-01");
      expect(call.headers["x-api-key"]).toBe("upstream-key-placeholder-not-a-credential");
      expect((call.body as { max_tokens?: number }).max_tokens).toBe(64);
    } finally {
      upstream.restore();
    }
  });

  it("serves an Anthropic-protocol request from an OPENAI upstream", async () => {
    const upstream = interceptUpstream(() => upstreamJson(OPENAI_COMPLETION));
    try {
      const message = await anthropicClient().messages.create({
        model: "claude-on-openai",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi" }],
      });

      // Translated IN: the upstream got a chat-completions body.
      expect(upstream.last().url).toBe("https://api.openai.conformance.test/v1/chat/completions");
      expect((upstream.last().body as { messages: unknown[] }).messages).toHaveLength(1);

      // Translated OUT: the SDK got a well-formed `Message`.
      expect(message.type).toBe("message");
      expect(message.role).toBe("assistant");
      const block = message.content[0];
      if (block?.type !== "text") throw new Error("expected a text block");
      expect(block.text).toBe("hello from an openai upstream");
      expect(message.stop_reason).toBe("end_turn");
      expect(message.usage).toMatchObject({ input_tokens: 7, output_tokens: 6 });
    } finally {
      upstream.restore();
    }
  });

  it("accumulates a translated stream through messages.stream()", async () => {
    const upstream = interceptUpstream(() => upstreamSse(OPENAI_STREAM));
    try {
      const stream = anthropicClient().messages.stream({
        model: "claude-on-openai",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi" }],
      });

      // `finalMessage()` is the strict path: `MessageStream` folds the frame
      // sequence into a `Message` and throws if the sequence is inconsistent.
      const message = await stream.finalMessage();
      const block = message.content[0];
      if (block?.type !== "text") throw new Error("expected a text block");
      expect(block.text).toBe("FerroGate");
      expect(message.stop_reason).toBe("end_turn");
      expect(message.usage).toMatchObject({ input_tokens: 4, output_tokens: 3 });
    } finally {
      upstream.restore();
    }
  });

  it("emits the Anthropic event sequence the raw stream API expects", async () => {
    const upstream = interceptUpstream(() => upstreamSse(OPENAI_STREAM));
    try {
      const stream = await anthropicClient().messages.create({
        model: "claude-on-openai",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      const events: string[] = [];
      const text: string[] = [];
      for await (const event of stream) {
        events.push(event.type);
        if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
          text.push(event.delta.text);
        }
      }

      // The SDK yields ONLY frames whose `event:` name it recognises, so an
      // unnamed or misnamed frame would silently vanish from this list rather
      // than throw — which is exactly why the sequence is asserted in full.
      expect(events[0]).toBe("message_start");
      expect(events).toContain("content_block_start");
      expect(events).toContain("content_block_delta");
      expect(events).toContain("content_block_stop");
      expect(events).toContain("message_delta");
      expect(events.at(-1)).toBe("message_stop");
      expect(text.join("")).toBe("FerroGate");
    } finally {
      upstream.restore();
    }
  });

  it("carries tool_use blocks in both directions", async () => {
    const toolMessage = {
      ...ANTHROPIC_MESSAGE,
      content: [
        { type: "tool_use", id: "toolu_1", name: "get_weather", input: { city: "Shanghai" } },
      ],
      stop_reason: "tool_use",
    };
    const upstream = interceptUpstream(() => upstreamJson(toolMessage));
    try {
      const message = await anthropicClient().messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 64,
        tools: [
          {
            name: "get_weather",
            description: "Look up the weather",
            input_schema: {
              type: "object",
              properties: { city: { type: "string" } },
              required: ["city"],
            },
          },
        ],
        messages: [{ role: "user", content: "weather in Shanghai?" }],
      });

      const block = message.content[0];
      if (block?.type !== "tool_use") throw new Error("expected a tool_use block");
      expect(block.name).toBe("get_weather");
      expect(block.input).toEqual({ city: "Shanghai" });
      expect(message.stop_reason).toBe("tool_use");
    } finally {
      upstream.restore();
    }
  });

  it("relays system, tools, temperature and stop_sequences to an OPENAI upstream", async () => {
    const upstream = interceptUpstream(() => upstreamJson(OPENAI_COMPLETION));
    try {
      await anthropicClient().messages.create({
        model: "claude-on-openai",
        max_tokens: 64,
        system: "be brief",
        temperature: 0.3,
        stop_sequences: ["STOP"],
        tool_choice: { type: "auto" },
        tools: [
          {
            name: "get_weather",
            description: "Look up the weather",
            input_schema: {
              type: "object",
              properties: { city: { type: "string" } },
              required: ["city"],
            },
          },
        ],
        messages: [{ role: "user", content: "weather?" }],
      });

      // The translated body is COMPLETE on this leg — this is the control case
      // that makes the next test's finding a divergence rather than a design.
      const body = upstream.last().body as Record<string, unknown>;
      expect(body["temperature"]).toBe(0.3);
      expect(body["stop"]).toEqual(["STOP"]);
      expect(body["tool_choice"]).toBe("auto");
      expect(body["tools"]).toEqual([
        {
          type: "function",
          function: {
            name: "get_weather",
            description: "Look up the weather",
            parameters: {
              type: "object",
              properties: { city: { type: "string" } },
              required: ["city"],
            },
          },
        },
      ]);
      expect((body["messages"] as Array<Record<string, unknown>>)[0]).toEqual({
        role: "system",
        content: "be brief",
      });
    } finally {
      upstream.restore();
    }
  });

  /**
   * THE MOST SERIOUS FINDING IN THIS SUITE, pinned exactly as the gateway
   * behaves today and deliberately NOT fixed here.
   *
   * `/v1/messages` is translated to a chat-completions body on the way in, and
   * `anthropicAdapter.buildUpstreamRequest`
   * (apps/gateway/src/inference/adapters.ts:355-380) then rebuilds a MINIMAL
   * native body from it — `model`, `messages`, `max_tokens`, `stream`, plus
   * `system` only if the translated body still had one, plus `tools` /
   * `tool_choice` only when the operation is `responses`. `/v1/messages` plans
   * as `chat_completions`, so on the Anthropic-upstream leg:
   *
   *   - `tools` and `tool_choice` are DROPPED — an Anthropic-SDK caller's tool
   *     definitions never reach the model, so it can never emit a `tool_use`
   *     block and agent loops silently degrade to plain text;
   *   - `temperature` and `stop_sequences` are DROPPED;
   *   - `system` arrives as a `{role:"system"}` entry INSIDE `messages`,
   *     because the inbound translation folded it there and the adapter copies
   *     `messages` verbatim. The real Anthropic Messages API accepts only
   *     `user` and `assistant` roles and takes `system` as a TOP-LEVEL
   *     parameter, so this body is one the upstream would reject outright.
   *
   * The same request served by an OPENAI upstream (test above) carries every
   * one of these correctly, which is what makes this a defect in one adapter
   * rather than a limit of the translation.
   */
  it("DIVERGENCE: the Anthropic-upstream leg drops system, tools, temperature and stop_sequences", async () => {
    const upstream = interceptUpstream(() => upstreamJson(ANTHROPIC_MESSAGE));
    try {
      await anthropicClient().messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 64,
        system: "be brief",
        temperature: 0.3,
        stop_sequences: ["STOP"],
        tool_choice: { type: "auto" },
        tools: [
          {
            name: "get_weather",
            description: "Look up the weather",
            input_schema: {
              type: "object",
              properties: { city: { type: "string" } },
              required: ["city"],
            },
          },
        ],
        messages: [{ role: "user", content: "weather?" }],
      });

      const body = upstream.last().body as Record<string, unknown>;
      expect(body["tools"]).toBeUndefined();
      expect(body["tool_choice"]).toBeUndefined();
      expect(body["temperature"]).toBeUndefined();
      expect(body["stop_sequences"]).toBeUndefined();
      expect(body["system"]).toBeUndefined();
      // …and the system prompt is smuggled in as a role the Anthropic API
      // does not accept.
      expect((body["messages"] as Array<Record<string, unknown>>)[0]).toEqual({
        role: "system",
        content: "be brief",
      });
    } finally {
      upstream.restore();
    }
  });
});

describe("@anthropic-ai/sdk — error taxonomy", () => {
  it("classifies 401 and 403 into the right subclasses", async () => {
    const unauthorized = await captured(() =>
      anthropicClient({ apiKey: "fg_not_a_key" }).messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 16,
        messages: [{ role: "user", content: "hi" }],
      }),
    );
    expect(unauthorized).toBeInstanceOf(AuthenticationError);
    expect(unauthorized.status).toBe(401);

    const forbidden = await captured(() =>
      anthropicClient({ apiKey: "fg_conformance_tenant_down" }).messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 16,
        messages: [{ role: "user", content: "hi" }],
      }),
    );
    expect(forbidden).toBeInstanceOf(PermissionDeniedError);
    expect(forbidden.status).toBe(403);
  });

  it("DIVERGENCE: the error body is not Anthropic-shaped, so message and requestID degrade", async () => {
    const error = await captured(() =>
      anthropicClient({ apiKey: "fg_not_a_key" }).messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 16,
        messages: [{ role: "user", content: "hi" }],
      }),
    );

    // Anthropic's native envelope is `{"type":"error","error":{"type":
    // "authentication_error","message":"..."}}`, and its `APIError` reads the
    // TOP-LEVEL `message`. FerroGate's envelope has no top-level `message`, so
    // `makeMessage` falls back to `JSON.stringify(body)` and the exception text
    // an operator sees in a log is the whole JSON document.
    expect(error.message).toContain('"code":"invalid_api_key"');
    expect(error.message).toContain("ferrogate_error");

    // `err.type` is Anthropic's error TAXONOMY member, e.g.
    // `authentication_error`. FerroGate supplies its single constant instead,
    // so `err.type`-based handling never matches.
    expect(error.type).toBe("ferrogate_error");

    // `requestID` is read from the `request-id` header. FerroGate emits
    // `x-request-id` (the OpenAI spelling) and nothing else, so an Anthropic-SDK
    // caller has NO correlation id at all — the id is only in the body.
    expect(error.requestID).toBeNull();
    expect((error.error as { error?: { request_id?: string } })?.error?.request_id).toEqual(
      expect.any(String),
    );
  });

  it("DIVERGENCE: messages.countTokens() is not routed", async () => {
    const error = await captured(() =>
      anthropicClient().messages.countTokens({
        model: "claude-3-5-sonnet-20241022",
        messages: [{ role: "user", content: "hi" }],
      }),
    );

    // `POST /v1/messages/count_tokens` is part of the Anthropic surface the SDK
    // exposes; FerroGate routes `/v1/messages` only. Reported, not fixed.
    expect(error.status).toBe(404);
    expect(error.message).toContain("no route for POST /v1/messages/count_tokens");
  });

  it("DIVERGENCE: models.list() answers in the OpenAI dialect", async () => {
    const page = await anthropicClient().models.list();

    // The call SUCCEEDS — `GET /v1/models` exists — but the gateway serves the
    // OpenAI model object (`{id, object:"model", created, owned_by}`) on both
    // ingresses. The Anthropic SDK's `ModelInfo` is `{id, type:"model",
    // display_name, created_at}`, so an Anthropic-native caller reading
    // `model.display_name` gets `undefined` rather than an error.
    const first = page.data[0] as unknown as Record<string, unknown>;
    expect(first?.["id"]).toEqual(expect.any(String));
    expect(first?.["object"]).toBe("model");
    expect(first?.["type"]).toBeUndefined();
    expect(first?.["display_name"]).toBeUndefined();
  });
});
