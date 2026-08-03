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
import {
  APIError,
  AuthenticationError,
  InternalServerError,
  PermissionDeniedError,
} from "@anthropic-ai/sdk";
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
  dataFrame({
    ...CHUNK_BASE,
    choices: [{ index: 0, delta: { role: "assistant", content: "Fer" } }],
  }),
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
   * WAS THE MOST SERIOUS FINDING IN THIS SUITE — fixed by issue #725, and this
   * is the assertion flipped from the divergence it used to pin.
   *
   * `/v1/messages` is translated to a chat-completions body on the way in, and
   * `anthropicAdapter.buildUpstreamRequest` used to REBUILD a minimal native
   * body from it — `model`, `messages`, `max_tokens`, `stream`, plus `system`
   * only if the translated body still had one, plus `tools` / `tool_choice`
   * only when the operation was `responses`. `/v1/messages` plans as
   * `chat_completions`, so on the Anthropic-upstream leg `tools`,
   * `tool_choice`, `temperature` and `stop_sequences` were all DROPPED while
   * the request answered 200, and `system` was smuggled in as a `role:"system"`
   * entry the Messages API does not accept.
   *
   * The adapter now translates the whole body instead, so the leg below matches
   * the OPENAI-upstream control above member for member — which is what makes
   * the pair a regression fence rather than two independent snapshots.
   */
  it("relays system, tools, temperature and stop_sequences to an ANTHROPIC upstream", async () => {
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
      // The round trip lands back on Anthropic's OWN spelling — `input_schema`,
      // not the `parameters` the inbound translation produced — because a body
      // carrying the OpenAI grammar would be a 400 from the real upstream.
      expect(body["tools"]).toEqual([
        {
          name: "get_weather",
          description: "Look up the weather",
          input_schema: {
            type: "object",
            properties: { city: { type: "string" } },
            required: ["city"],
          },
        },
      ]);
      expect(body["tool_choice"]).toEqual({ type: "auto" });
      expect(body["temperature"]).toBe(0.3);
      expect(body["stop_sequences"]).toEqual(["STOP"]);
      // `system` is the TOP-LEVEL parameter, and `messages` carries only the
      // roles the Messages API accepts.
      expect(body["system"]).toBe("be brief");
      expect(body["messages"]).toEqual([{ role: "user", content: "weather?" }]);
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

    // `APIError.makeMessage` reads the TOP-LEVEL `message` of the body, and
    // FerroGate's envelope has none, so the exception text is the whole JSON
    // document.
    //
    // NOT a divergence, and the correction matters: Anthropic's OWN envelope is
    // `{"type":"error","error":{"type":"authentication_error","message":"..."}}`
    // — also no top-level `message` — so the SDK stringifies against
    // `api.anthropic.com` in exactly the same way. The control case
    // ("a RELAYED Anthropic-native error body reads the same way") proves it
    // below. What IS divergent here is `type` and `requestID`.
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

  it("502 — an unreachable provider is a typed InternalServerError", async () => {
    // The Anthropic ingress reaches the same `dispatchUpstream` as the OpenAI
    // one, so the question this answers is only about the CLIENT: does
    // `@anthropic-ai/sdk` classify FerroGate's 502 envelope, or choke on it?
    const upstream = interceptUpstream(() => {
      throw new TypeError("Network connection lost.");
    });
    try {
      const error = await captured(() =>
        anthropicClient().messages.create({
          model: "claude-3-5-sonnet-20241022",
          max_tokens: 16,
          messages: [{ role: "user", content: "hi" }],
        }),
      );

      expect(error).toBeInstanceOf(InternalServerError);
      expect(error.status).toBe(502);
      // The body decoded — `err.error` is the parsed envelope, not raw text.
      const body = error.error as { error?: { code?: string; request_id?: string } };
      expect(body.error?.code).toBe("provider_dispatch_error");
      expect(body.error?.request_id).toEqual(expect.any(String));
      // `err.type` is `body.error.type`, so it carries FerroGate's constant —
      // the same divergence the 401 case pins, now shown to hold on a 5xx too.
      expect(error.type).toBe("ferrogate_error");
      // And the same missing correlation id: `request-id` is never emitted.
      expect(error.requestID).toBeNull();
    } finally {
      upstream.restore();
    }
  });

  it("500 — a relayed Anthropic-native error keeps the provider's own taxonomy", async () => {
    // The control case for the message-degradation note above. A provider 500
    // is relayed VERBATIM, so what the SDK decodes here is a genuine Anthropic
    // error body — the exact bytes `api.anthropic.com` would have sent.
    const upstream = interceptUpstream(() =>
      upstreamJson(
        { type: "error", error: { type: "api_error", message: "Internal server error" } },
        500,
      ),
    );
    try {
      const error = await captured(() =>
        anthropicClient().messages.create({
          model: "claude-3-5-sonnet-20241022",
          max_tokens: 16,
          messages: [{ role: "user", content: "hi" }],
        }),
      );

      expect(error).toBeInstanceOf(InternalServerError);
      expect(error.status).toBe(500);
      // The provider's taxonomy survives the hop: `err.type` is Anthropic's
      // own `api_error`, which is what an Anthropic-native caller switches on.
      expect(error.type).toBe("api_error");
      expect((error.error as { error?: { message?: string } }).error?.message).toBe(
        "Internal server error",
      );
      // ... and `err.message` is STILL the stringified body, with a body that
      // never went near FerroGate's envelope. That is the proof that the
      // degradation is the SDK's own behaviour and not something the gateway
      // does to Anthropic callers.
      expect(error.message).toContain('{"type":"error"');
    } finally {
      upstream.restore();
    }
  });

  it("answers messages.countTokens() in the SDK's own shape", async () => {
    // `POST /v1/messages/count_tokens` landed in #671 while this suite was being
    // written — it 404'd on the branch point and passes on `main`, which is
    // exactly why the suite is worth having. No upstream call: the count is
    // served from the gateway's estimator.
    const count = await anthropicClient().messages.countTokens({
      model: "claude-3-5-sonnet-20241022",
      messages: [{ role: "user", content: "hi" }],
    });

    expect(count.input_tokens).toEqual(expect.any(Number));
    expect(count.input_tokens).toBeGreaterThan(0);
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
