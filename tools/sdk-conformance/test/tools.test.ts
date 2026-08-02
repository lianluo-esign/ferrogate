/**
 * Tool / function calling, buffered and streamed.
 *
 * Tool calls are the second-most-likely divergence after streaming, for a
 * structural reason: the arguments arrive as a STRING that the SDK assembles
 * from fragments spread across chunks, keyed by `index`. A relay that reorders
 * frames, coalesces deltas, or drops the `index` produces JSON that no longer
 * parses — and the failure surfaces in the caller's `JSON.parse`, far from the
 * gateway.
 *
 * The accumulation is done by the SDK's own `ChatCompletionStream`, so what is
 * asserted is what an application would actually observe.
 */
import { describe, expect, it } from "vitest";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import {
  DONE_FRAME,
  dataFrame,
  interceptUpstream,
  openaiClient,
  upstreamJson,
  upstreamSse,
} from "./harness.js";

const WEATHER_TOOL: ChatCompletionTool = {
  type: "function",
  function: {
    name: "get_weather",
    description: "Look up the weather for a city",
    parameters: {
      type: "object",
      properties: { city: { type: "string" } },
      required: ["city"],
      additionalProperties: false,
    },
  },
};

const TOOL_COMPLETION = {
  id: "chatcmpl-tools",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
  choices: [
    {
      index: 0,
      message: {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "call_abc123",
            type: "function",
            function: { name: "get_weather", arguments: '{"city":"Shanghai"}' },
          },
        ],
      },
      finish_reason: "tool_calls",
    },
  ],
  usage: { prompt_tokens: 40, completion_tokens: 12, total_tokens: 52 },
};

const CHUNK_BASE = {
  id: "chatcmpl-tools-stream",
  object: "chat.completion.chunk",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
};

/** The arguments string arrives in four fragments, as a real provider sends it. */
const TOOL_STREAM = [
  dataFrame({
    ...CHUNK_BASE,
    choices: [
      {
        index: 0,
        delta: {
          role: "assistant",
          tool_calls: [
            { index: 0, id: "call_abc123", type: "function", function: { name: "get_weather", arguments: "" } },
          ],
        },
      },
    ],
  }),
  dataFrame({
    ...CHUNK_BASE,
    choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"ci' } }] } }],
  }),
  dataFrame({
    ...CHUNK_BASE,
    choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'ty":"Sha' } }] } }],
  }),
  dataFrame({
    ...CHUNK_BASE,
    choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'nghai"}' } }] } }],
  }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
  DONE_FRAME,
];

describe("openai SDK — tool calls", () => {
  it("parses a buffered tool call", async () => {
    const upstream = interceptUpstream(() => upstreamJson(TOOL_COMPLETION));
    try {
      const completion = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "weather in Shanghai?" }],
        tools: [WEATHER_TOOL],
        tool_choice: "auto",
      });

      const call = completion.choices[0]?.message.tool_calls?.[0];
      expect(call?.type).toBe("function");
      expect(call?.id).toBe("call_abc123");
      // Narrowed by the SDK's own discriminated union.
      if (call?.type !== "function") throw new Error("expected a function tool call");
      expect(call.function.name).toBe("get_weather");
      expect(JSON.parse(call.function.arguments)).toEqual({ city: "Shanghai" });
      expect(completion.choices[0]?.finish_reason).toBe("tool_calls");
    } finally {
      upstream.restore();
    }
  });

  it("relays the tool declarations to the provider unaltered", async () => {
    const upstream = interceptUpstream(() => upstreamJson(TOOL_COMPLETION));
    try {
      await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "weather?" }],
        tools: [WEATHER_TOOL],
        tool_choice: { type: "function", function: { name: "get_weather" } },
        parallel_tool_calls: false,
      });

      const body = upstream.last().body as Record<string, unknown>;
      // A gateway that dropped or rewrote any of these would change which tool
      // the model may call — a correctness change, not a transport detail.
      expect(body["tools"]).toEqual([WEATHER_TOOL]);
      expect(body["tool_choice"]).toEqual({
        type: "function",
        function: { name: "get_weather" },
      });
      expect(body["parallel_tool_calls"]).toBe(false);
    } finally {
      upstream.restore();
    }
  });

  it("reassembles fragmented tool arguments across streamed chunks", async () => {
    const upstream = interceptUpstream(() => upstreamSse(TOOL_STREAM));
    try {
      const runner = openaiClient().chat.completions.stream({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "weather in Shanghai?" }],
        tools: [WEATHER_TOOL],
      });

      const completion = await runner.finalChatCompletion();
      const call = completion.choices[0]?.message.tool_calls?.[0];
      if (call?.type !== "function") throw new Error("expected a function tool call");
      // Four fragments, one valid JSON document. This is the assertion that
      // goes red if the relay ever coalesces or reorders frames.
      expect(JSON.parse(call.function.arguments)).toEqual({ city: "Shanghai" });
      expect(call.function.name).toBe("get_weather");
      expect(completion.choices[0]?.finish_reason).toBe("tool_calls");
    } finally {
      upstream.restore();
    }
  });

  it("accepts a tool RESULT turn on the way back in", async () => {
    // The second half of a tool round-trip: `role:"tool"` messages carrying a
    // `tool_call_id`, plus an assistant turn with `tool_calls`. Gateways that
    // validate messages too strictly reject exactly this shape.
    const upstream = interceptUpstream(() => upstreamJson(TOOL_COMPLETION));
    try {
      await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          { role: "user", content: "weather in Shanghai?" },
          {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "call_abc123",
                type: "function",
                function: { name: "get_weather", arguments: '{"city":"Shanghai"}' },
              },
            ],
          },
          { role: "tool", tool_call_id: "call_abc123", content: '{"temp_c":31}' },
        ],
        tools: [WEATHER_TOOL],
      });

      const body = upstream.last().body as { messages: Array<Record<string, unknown>> };
      expect(body.messages).toHaveLength(3);
      expect(body.messages[2]).toMatchObject({
        role: "tool",
        tool_call_id: "call_abc123",
      });
    } finally {
      upstream.restore();
    }
  });
});
