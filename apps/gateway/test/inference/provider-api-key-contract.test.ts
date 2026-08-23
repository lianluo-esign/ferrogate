import { describe, expect, it } from "vitest";

import type { PhysicalRoute, Usage } from "../../src/inference/index.js";
import { routePriceSettledCostUsd } from "../../src/metering/index.js";
import { harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson, providerSse } from "./provider-mock.js";

const INPUT_PRICE_PER_1M = 2;
const OUTPUT_PRICE_PER_1M = 10;
const EXPECTED_COST_USD = (100 * INPUT_PRICE_PER_1M + 50 * OUTPUT_PRICE_PER_1M) / 1_000_000;

type ProviderCase = {
  readonly name: string;
  readonly kind: string;
  readonly model: string;
  readonly baseUrl: string;
  readonly expectedUrl: string;
  readonly expectedApiKeyHeader: "authorization" | "x-api-key" | "x-goog-api-key";
  readonly response: unknown;
};

const CHAT_CASES: readonly ProviderCase[] = [
  {
    name: "OpenAI",
    kind: "openai",
    model: "gpt-5.5",
    baseUrl: "https://api.openai.test/v1",
    expectedUrl: "https://api.openai.test/v1/chat/completions",
    expectedApiKeyHeader: "authorization",
    response: {
      id: "chatcmpl-openai",
      object: "chat.completion",
      model: "gpt-5.5",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
    },
  },
  {
    name: "Anthropic",
    kind: "anthropic",
    model: "claude-sonnet-4-6",
    baseUrl: "https://api.anthropic.test/v1",
    expectedUrl: "https://api.anthropic.test/v1/messages",
    expectedApiKeyHeader: "x-api-key",
    response: {
      id: "msg-anthropic",
      type: "message",
      model: "claude-sonnet-4-6",
      content: [{ type: "text", text: "hi" }],
      stop_reason: "end_turn",
      usage: { input_tokens: 100, output_tokens: 50 },
    },
  },
  {
    name: "Grok",
    kind: "grok",
    model: "grok-4",
    baseUrl: "https://api.x.ai/v1",
    expectedUrl: "https://api.x.ai/v1/chat/completions",
    expectedApiKeyHeader: "authorization",
    response: {
      id: "chatcmpl-grok",
      object: "chat.completion",
      model: "grok-4",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
    },
  },
  {
    name: "Gemini",
    kind: "gemini",
    model: "gemini-2.5-pro",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta",
    expectedUrl:
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent",
    expectedApiKeyHeader: "x-goog-api-key",
    response: {
      responseId: "gemini-response",
      modelVersion: "gemini-2.5-pro",
      candidates: [
        {
          content: { role: "model", parts: [{ text: "hi" }] },
          finishReason: "STOP",
        },
      ],
      usageMetadata: {
        promptTokenCount: 100,
        candidatesTokenCount: 40,
        thoughtsTokenCount: 10,
        totalTokenCount: 150,
      },
    },
  },
  {
    name: "DeepSeek",
    kind: "deepseek",
    model: "deepseek-chat",
    baseUrl: "https://api.deepseek.test/v1",
    expectedUrl: "https://api.deepseek.test/v1/chat/completions",
    expectedApiKeyHeader: "authorization",
    response: {
      id: "chatcmpl-deepseek",
      object: "chat.completion",
      model: "deepseek-chat",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
    },
  },
];

function route(entry: ProviderCase): PhysicalRoute {
  return {
    logicalModel: `${entry.kind}-logical`,
    provider: `${entry.kind}-provider`,
    providerModel: entry.model,
    providerKind: entry.kind,
    baseUrl: entry.baseUrl,
    apiKey: "provider-api-key",
    enabled: true,
    inputPricePer1m: INPUT_PRICE_PER_1M,
    outputPricePer1m: OUTPUT_PRICE_PER_1M,
  };
}

function assertApiKeyHeader(entry: ProviderCase, headers: Record<string, string>): void {
  const expectedValue =
    entry.expectedApiKeyHeader === "authorization" ? "Bearer provider-api-key" : "provider-api-key";
  expect(headers[entry.expectedApiKeyHeader]).toBe(expectedValue);
  if (entry.expectedApiKeyHeader !== "authorization") expect(headers.authorization).toBeUndefined();
  if (entry.expectedApiKeyHeader !== "x-api-key") expect(headers["x-api-key"]).toBeUndefined();
  if (entry.expectedApiKeyHeader !== "x-goog-api-key") {
    expect(headers["x-goog-api-key"]).toBeUndefined();
  }
}

describe("API-key provider protocol and billing contract", () => {
  it.each(CHAT_CASES)(
    "$name sends the correct API-key protocol and settles native usage",
    async (entry) => {
      const upstream = interceptProviderFetch(() => providerJson(entry.response));
      try {
        const physicalRoute = route(entry);
        const gateway = harness({}, [physicalRoute]);
        const response = await gateway.post("/v1/chat/completions", {
          model: physicalRoute.logicalModel,
          messages: [{ role: "user", content: "hi" }],
        });

        expect(response.status).toBe(200);
        const sent = upstream.lastRequest();
        expect(sent.url).toBe(entry.expectedUrl);
        assertApiKeyHeader(entry, sent.headers);

        const body = (await response.json()) as {
          object?: string;
          choices?: Array<{ message?: { content?: string } }>;
        };
        expect(body.object).toBe("chat.completion");
        expect(body.choices?.[0]?.message?.content).toBe("hi");

        const usage = gateway.usage.last as Usage | undefined;
        expect(usage).toMatchObject({
          promptTokens: 100,
          completionTokens: 50,
          totalTokens: 150,
        });
        expect(routePriceSettledCostUsd(usage as Usage)).toBeCloseTo(EXPECTED_COST_USD, 12);
      } finally {
        upstream.restore();
      }
    },
  );

  it("bills the real OpenAI Responses input/output token field names", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerJson({
        id: "resp-openai",
        object: "response",
        model: entry.model,
        output: [
          {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "hi" }],
          },
        ],
        usage: { input_tokens: 100, output_tokens: 50, total_tokens: 150 },
      }),
    );
    try {
      const physicalRoute = route(entry);
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/responses", {
        model: physicalRoute.logicalModel,
        input: "hi",
      });

      expect(response.status).toBe(200);
      expect(gateway.usage.last).toMatchObject({ promptTokens: 100, completionTokens: 50 });
      expect(routePriceSettledCostUsd(gateway.usage.last as Usage)).toBeCloseTo(
        EXPECTED_COST_USD,
        12,
      );
    } finally {
      upstream.restore();
    }
  });

  it("serves Chat clients through an explicitly Responses-only provider", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerJson({
        id: "resp-chat-bridge",
        object: "response",
        model: entry.model,
        output: [
          {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "hi" }],
          },
        ],
        usage: { input_tokens: 100, output_tokens: 50, total_tokens: 150 },
      }),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
      });

      expect(response.status).toBe(200);
      expect(upstream.lastRequest()).toMatchObject({
        url: "https://api.openai.test/v1/responses",
        body: {
          model: entry.model,
          input: [{ role: "user", content: "hi" }],
          stream: false,
        },
      });
      const body = (await response.json()) as {
        object?: string;
        choices?: Array<{ message?: { content?: string } }>;
      };
      expect(body.object).toBe("chat.completion");
      expect(body.choices?.[0]?.message?.content).toBe("hi");
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
    } finally {
      upstream.restore();
    }
  });

  it("serves Anthropic Messages clients through a Responses-only provider", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerJson({
        id: "resp-messages-bridge",
        object: "response",
        model: entry.model,
        output: [
          {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "hi" }],
          },
        ],
        usage: { input_tokens: 100, output_tokens: 50, total_tokens: 150 },
      }),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/messages", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
      });

      expect(response.status).toBe(200);
      expect(upstream.lastRequest()).toMatchObject({
        url: "https://api.openai.test/v1/responses",
        body: {
          model: entry.model,
          input: [{ role: "user", content: "hi" }],
          stream: false,
        },
      });
      expect(await response.json()).toMatchObject({
        type: "message",
        model: entry.model,
        content: [{ type: "text", text: "hi" }],
        usage: { input_tokens: 100, output_tokens: 50 },
      });
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
    } finally {
      upstream.restore();
    }
  });

  it("streams Anthropic Messages events through a Responses-only provider", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'event: response.created\ndata: {"type":"response.created","response":{"id":"resp-stream","model":"gpt-5.5"}}',
        'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"hi"}',
        'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp-stream","model":"gpt-5.5","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}}}',
      ]),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/messages", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(upstream.lastRequest()).toMatchObject({
        url: "https://api.openai.test/v1/responses",
        body: { stream: true },
      });
      expect(body).toContain("event: message_start");
      expect(body).toContain('"type":"text_delta","text":"hi"');
      expect(body).toContain('"input_tokens":100');
      expect(body).toContain('"output_tokens":50');
      expect(body).toContain("event: message_stop");
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
    } finally {
      upstream.restore();
    }
  });

  it("maps Chat tool and image turns onto the Responses input contract", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerJson({
        id: "resp-agent-bridge",
        object: "response",
        model: entry.model,
        output: [
          {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "done" }],
          },
        ],
        usage: { input_tokens: 20, output_tokens: 5, total_tokens: 25 },
      }),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [
          {
            role: "user",
            content: [
              { type: "text", text: "inspect" },
              { type: "image_url", image_url: { url: "https://example.test/a.png" } },
            ],
          },
          {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "call_weather",
                type: "function",
                function: { name: "weather", arguments: '{"city":"Singapore"}' },
              },
            ],
          },
          { role: "tool", tool_call_id: "call_weather", content: '{"degrees":30}' },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "weather",
              description: "Read weather",
              parameters: { type: "object" },
            },
          },
        ],
        max_completion_tokens: 50,
        response_format: { type: "json_object" },
        frequency_penalty: 0.5,
      });

      expect(response.status).toBe(200);
      expect(upstream.lastRequest().body).toMatchObject({
        model: entry.model,
        input: [
          {
            role: "user",
            content: [
              { type: "input_text", text: "inspect" },
              { type: "input_image", image_url: "https://example.test/a.png" },
            ],
          },
          {
            type: "function_call",
            call_id: "call_weather",
            name: "weather",
            arguments: '{"city":"Singapore"}',
          },
          {
            type: "function_call_output",
            call_id: "call_weather",
            output: '{"degrees":30}',
          },
        ],
        tools: [
          {
            type: "function",
            name: "weather",
            description: "Read weather",
            parameters: { type: "object" },
          },
        ],
        max_output_tokens: 50,
        text: { format: { type: "json_object" } },
      });
      expect(upstream.lastRequest().body).not.toHaveProperty("frequency_penalty");
    } finally {
      upstream.restore();
    }
  });

  it("normalizes Responses SSE for a streaming Chat client", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"hi"}',
        'event: response.completed\ndata: {"type":"response.completed","response":{"model":"gpt-5.5","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}}}',
      ]),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const text = await response.text();

      expect(response.status).toBe(200);
      expect(upstream.lastRequest().url).toBe("https://api.openai.test/v1/responses");
      expect(text).toContain('"object":"chat.completion.chunk"');
      expect(text).toContain('"content":"hi"');
      expect(text.endsWith("data: [DONE]\n\n")).toBe(true);
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
    } finally {
      upstream.restore();
    }
  });

  it("keeps the Responses call_id stable across streamed tool argument deltas", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'event: response.output_item.added\ndata: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_weather","type":"function_call","call_id":"call_weather","name":"weather","arguments":""}}',
        'event: response.function_call_arguments.delta\ndata: {"type":"response.function_call_arguments.delta","item_id":"fc_weather","output_index":0,"delta":"{\\"city\\":\\"Singapore\\"}"}',
        'event: response.completed\ndata: {"type":"response.completed","response":{"model":"gpt-5.5","usage":{"input_tokens":20,"output_tokens":5,"total_tokens":25}}}',
      ]),
    );
    try {
      const physicalRoute: PhysicalRoute = {
        ...route(entry),
        upstreamProtocol: "openai.responses",
      };
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "weather" }],
        stream: true,
      });
      const text = await response.text();

      expect(response.status).toBe(200);
      expect(text).toContain('"id":"call_weather"');
      expect(text).not.toContain('"id":"fc_weather"');
      expect(text).toContain('"arguments":"{\\"city\\":\\"Singapore\\"}"');
      expect(text.endsWith("data: [DONE]\n\n")).toBe(true);
    } finally {
      upstream.restore();
    }
  });

  it("bills usage nested in a streamed OpenAI response.completed event", async () => {
    const entry = CHAT_CASES[0] as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"hi"}',
        'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp-stream","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}}}',
      ]),
    );
    try {
      const physicalRoute = route(entry);
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/responses", {
        model: physicalRoute.logicalModel,
        input: "hi",
        stream: true,
      });
      await response.text();

      expect(response.status).toBe(200);
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
      expect(routePriceSettledCostUsd(gateway.usage.last as Usage)).toBeCloseTo(
        EXPECTED_COST_USD,
        12,
      );
    } finally {
      upstream.restore();
    }
  });

  it.each(CHAT_CASES.filter((entry) => entry.kind === "anthropic" || entry.kind === "gemini"))(
    "$name normalizes a native buffered answer for the Responses ingress",
    async (entry) => {
      const upstream = interceptProviderFetch(() => providerJson(entry.response));
      try {
        const physicalRoute = route(entry);
        const gateway = harness({}, [physicalRoute]);
        const response = await gateway.post("/v1/responses", {
          model: physicalRoute.logicalModel,
          input: "hi",
        });

        expect(response.status).toBe(200);
        const sent = upstream.lastRequest();
        if (entry.kind === "anthropic") {
          expect(sent.body).toMatchObject({
            model: entry.model,
            messages: [{ role: "user", content: "hi" }],
          });
        } else {
          expect(sent.body).toMatchObject({
            contents: [{ role: "user", parts: [{ text: "hi" }] }],
          });
        }
        const body = (await response.json()) as {
          object?: string;
          output?: Array<{ content?: Array<{ text?: string }> }>;
          usage?: { input_tokens?: number; output_tokens?: number };
        };
        expect(body.object).toBe("response");
        expect(body.output?.[0]?.content?.[0]?.text).toBe("hi");
        expect(body.usage).toMatchObject({ input_tokens: 100, output_tokens: 50 });
        expect(gateway.usage.last).toMatchObject({
          promptTokens: 100,
          completionTokens: 50,
          totalTokens: 150,
        });
        expect(routePriceSettledCostUsd(gateway.usage.last as Usage)).toBeCloseTo(
          EXPECTED_COST_USD,
          12,
        );
      } finally {
        upstream.restore();
      }
    },
  );

  it("normalizes and bills a native Anthropic stream for OpenAI chat clients", async () => {
    const entry = CHAT_CASES.find((candidate) => candidate.kind === "anthropic") as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_stream","model":"claude-test","usage":{"input_tokens":100,"cache_read_input_tokens":20,"cache_creation_input_tokens":10,"output_tokens":0}}}',
        'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}',
        'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}',
        'event: message_stop\ndata: {"type":"message_stop"}',
      ]),
    );
    try {
      const physicalRoute = route(entry);
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(body).toContain('"object":"chat.completion.chunk"');
      expect(body).toContain('"content":"hi"');
      expect(body).not.toContain("event: message_start");
      expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 130,
        completionTokens: 50,
        totalTokens: 180,
        cachedInputTokens: 20,
        cacheWriteTokens: 10,
      });
    } finally {
      upstream.restore();
    }
  });

  it("normalizes and bills a native Gemini stream for OpenAI chat clients", async () => {
    const entry = CHAT_CASES.find((candidate) => candidate.kind === "gemini") as ProviderCase;
    const upstream = interceptProviderFetch(() =>
      providerSse([
        'data: {"responseId":"gemini-stream","modelVersion":"gemini-test","candidates":[{"content":{"parts":[{"thought":true,"text":"r"},{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"cachedContentTokenCount":20,"candidatesTokenCount":40,"thoughtsTokenCount":10,"totalTokenCount":150}}',
      ]),
    );
    try {
      const physicalRoute = route(entry);
      const gateway = harness({}, [physicalRoute]);
      const response = await gateway.post("/v1/chat/completions", {
        model: physicalRoute.logicalModel,
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(body).toContain('"reasoning_content":"r"');
      expect(body).toContain('"content":"hi"');
      expect(body).not.toContain("usageMetadata");
      expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
      expect(gateway.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
        cachedInputTokens: 20,
        reasoningTokens: 10,
      });
    } finally {
      upstream.restore();
    }
  });
});
