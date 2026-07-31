import { describe, expect, test } from "vitest";

import {
  AdapterError,
  AnthropicAdapter,
  AzureOpenAiAdapter,
  BedrockAdapter,
  GeminiAdapter,
  GrokAdapter,
  OpenAiCompatibleAdapter,
  OpenRouterAdapter,
  SecretValue,
  VertexAiAdapter,
} from "../src/index.js";
import type { ProviderConfig, ProviderHeader } from "../src/index.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const headerValue = (headers: ProviderHeader[], name: string): string | undefined =>
  headers.find((header) => header.name === name)?.value.exposeSecret();
const hasBearer = (headers: ProviderHeader[], secret: string): boolean =>
  headers.some((header) => header.value.exposeSecret() === `Bearer ${secret}`);

function openaiProvider(apiKey?: string): ProviderConfig {
  return { name: "openai", kind: "openai", baseUrl: "https://api.openai.example/v1/", apiKey };
}

describe("OpenAiCompatibleAdapter", () => {
  test("rewrites logical model to provider model and preserves body", () => {
    const prepared = new OpenAiCompatibleAdapter().prepareChatCompletions(openaiProvider(), {
      logicalModel: "fast-chat",
      providerModel: "gpt-4o-mini",
      stream: false,
      body: { model: "fast-chat", messages: [{ role: "user", content: "hello" }] },
    });
    expect(prepared.endpoint).toBe("https://api.openai.example/v1/chat/completions");
    expect((prepared.body as Record<string, unknown>)["model"]).toBe("gpt-4o-mini");
    expect((prepared.body as Record<string, unknown>)["stream"]).toBe(false);
  });

  test("streaming sets include_usage and never leaks the secret in inspection", () => {
    const prepared = new OpenAiCompatibleAdapter().prepareChatCompletions(
      openaiProvider("provider-secret"),
      { logicalModel: "fast-chat", providerModel: "c", stream: true, body: { model: "x" } },
    );
    expect(prepared.stream).toBe(true);
    const body = prepared.body as Record<string, Record<string, unknown>>;
    expect(body["stream_options"]!["include_usage"]).toBe(true);
    expect(hasBearer(prepared.headers, "provider-secret")).toBe(true);
    // SecretValue redaction: no plaintext through JSON or string coercion.
    expect(JSON.stringify(prepared.headers)).not.toContain("provider-secret");
    expect(String(new SecretValue("provider-secret"))).toBe("<redacted>");
  });

  test("accepts every openai-compatible alias but rejects a foreign kind", () => {
    const adapter = new OpenAiCompatibleAdapter();
    for (const kind of ["openai", "deepseek", "vllm", "llama.cpp", "ollama-compatible"]) {
      const prepared = adapter.prepareChatCompletions(
        { ...openaiProvider(), kind },
        { logicalModel: "l", providerModel: "provider-chat", stream: false, body: { model: "l" } },
      );
      expect((prepared.body as Record<string, unknown>)["model"]).toBe("provider-chat");
    }
    expect(() =>
      adapter.prepareChatCompletions(
        { ...openaiProvider(), kind: "anthropic" },
        { logicalModel: "l", providerModel: "c", stream: false, body: { model: "l" } },
      ),
    ).toThrowError(/unsupported provider kind anthropic/);
  });

  test("rejects a non-object body (edge case)", () => {
    try {
      new OpenAiCompatibleAdapter().prepareChatCompletions(openaiProvider(), {
        logicalModel: "l",
        providerModel: "c",
        stream: false,
        body: "bad",
      });
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(AdapterError);
      expect((error as AdapterError).kind).toBe("InvalidRequest");
      expect((error as AdapterError).message).toBe("chat completion request body must be a JSON object");
    }
  });

  test("normalizes errors + extracts usage + round-trips tool calls", () => {
    const adapter = new OpenAiCompatibleAdapter();
    const normalized = adapter.normalizeErrorResponse(
      429,
      "application/json",
      bytes('{"error":{"message":"rate limited","type":"rate_limit_error","code":"rate_limit_exceeded"}}'),
      "fg-test",
    );
    const error = (normalized.body as Record<string, Record<string, unknown>>)["error"]!;
    expect(error["message"]).toBe("rate limited");
    expect(error["provider_type"]).toBe("rate_limit_error");
    expect(error["code"]).toBe("rate_limit_exceeded");

    expect(adapter.extractUsage(bytes('{"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}'))).toEqual(
      { promptTokens: 11, completionTokens: 7, totalTokens: 18 },
    );
    expect(adapter.extractUsage(bytes('{"id":"x"}'))).toBeUndefined();

    const calls = adapter.extractToolCalls(
      bytes('{"choices":[{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_weather","arguments":"{\\"city\\":\\"Shanghai\\"}"}}]}}]}'),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ id: "call_1", name: "lookup_weather" });
    expect((calls[0]!.arguments as Record<string, unknown>)["city"]).toBe("Shanghai");
  });

  test("non-JSON error falls back to the raw body text", () => {
    const normalized = new OpenAiCompatibleAdapter().normalizeErrorResponse(
      503,
      "text/plain",
      bytes("upstream unavailable"),
      "fg-test",
    );
    const error = (normalized.body as Record<string, Record<string, unknown>>)["error"]!;
    expect(error["message"]).toBe("upstream unavailable");
    expect(error["code"]).toBe("provider_error");
  });

  test("images generation is supported; embeddings + catalog work", () => {
    const adapter = new OpenAiCompatibleAdapter();
    const images = adapter.prepareImages(openaiProvider(), {
      logicalModel: "art",
      providerModel: "gpt-image-1",
      body: { model: "art", prompt: "a red fox", n: 2 },
    });
    expect(images.endpoint).toBe("https://api.openai.example/v1/images/generations");
    expect((images.body as Record<string, unknown>)["model"]).toBe("gpt-image-1");

    const catalog = adapter.parseModelCatalog(
      bytes('{"object":"list","data":[{"id":"gpt-4o-mini","owned_by":"openai","created":1715367049,"context_window":128000,"capabilities":["chat","tools"]}]}'),
    );
    expect(catalog[0]).toMatchObject({
      id: "gpt-4o-mini",
      ownedBy: "openai",
      created: 1715367049,
      contextWindow: 128000,
    });
    expect(catalog[0]!.capabilities).toEqual(["chat", "tools"]);
  });
});

describe("AnthropicAdapter", () => {
  const provider = (apiKey?: string): ProviderConfig => ({
    name: "anthropic",
    kind: "anthropic",
    baseUrl: "https://api.anthropic.example/v1/",
    apiKey,
  });

  test("chat plan → /messages request with x-api-key auth", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(provider("provider-secret"), {
      logicalModel: "claude-chat",
      providerModel: "claude-3-5-sonnet-latest",
      stream: true,
      body: {
        model: "claude-chat",
        messages: [{ role: "user", content: "hello" }],
        max_tokens: 256,
        system: "be concise",
      },
    });
    expect(prepared.endpoint).toBe("https://api.anthropic.example/v1/messages");
    const body = prepared.body as Record<string, unknown>;
    expect(body["model"]).toBe("claude-3-5-sonnet-latest");
    expect(body["max_tokens"]).toBe(256);
    expect(body["system"]).toBe("be concise");
    expect(body["stream"]).toBe(true);
    expect(headerValue(prepared.headers, "x-api-key")).toBe("provider-secret");
  });

  test("responses plan with tool_choice + image inputs translates to messages", () => {
    const prepared = new AnthropicAdapter().prepareResponses(provider(), {
      logicalModel: "claude-chat",
      providerModel: "claude-3-5-sonnet-latest",
      stream: false,
      body: {
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
              { type: "input_text", text: "look" },
              { type: "input_image", image_url: "https://example.com/a.png" },
            ],
          },
        ],
      },
    });
    const body = prepared.body as any;
    expect(body.tools[0].name).toBe("lookup_weather");
    expect(body.tool_choice.type).toBe("tool");
    expect(body.messages[0].content[0].type).toBe("text");
    expect(body.messages[0].content[1].type).toBe("image");
    expect(body.messages[0].content[1].source.type).toBe("url");
  });

  test("usage sums input+output; tool results become content blocks", () => {
    const adapter = new AnthropicAdapter();
    expect(adapter.extractUsage(bytes('{"usage":{"input_tokens":13,"output_tokens":8}}'))).toEqual({
      promptTokens: 13,
      completionTokens: 8,
      totalTokens: 21,
    });
    const body = adapter.appendToolResults({ messages: [{ role: "user", content: "weather?" }] }, [
      { tool_call_id: "toolu_1", content: { temp_c: 21 }, is_error: false },
    ]) as any;
    expect(body.messages[1].role).toBe("user");
    expect(body.messages[1].content[0].type).toBe("tool_result");
    expect(body.messages[1].content[0].content).toBe('{"temp_c":21}');
  });
});

describe("Azure / Grok / OpenRouter", () => {
  test("Azure puts the deployment in the URL and drops body model", () => {
    const prepared = new AzureOpenAiAdapter().prepareChatCompletions(
      {
        name: "azure",
        kind: "azure-openai",
        baseUrl: "https://example.openai.azure.com/?api-version=2024-02-15-preview",
        apiKey: "provider-secret",
      },
      { logicalModel: "fast", providerModel: "gpt-4o mini", stream: false, body: { model: "fast" } },
    );
    expect(prepared.endpoint).toBe(
      "https://example.openai.azure.com/openai/deployments/gpt-4o%20mini/chat/completions?api-version=2024-02-15-preview",
    );
    expect((prepared.body as Record<string, unknown>)["model"]).toBeUndefined();
    expect(headerValue(prepared.headers, "api-key")).toBe("provider-secret");
  });

  test("Azure defaults api-version when the base URL omits it", () => {
    const prepared = new AzureOpenAiAdapter().prepareChatCompletions(
      { name: "a", kind: "azure", baseUrl: "https://example.openai.azure.com/" },
      { logicalModel: "f", providerModel: "gpt-4o-mini", stream: false, body: { messages: [] } },
    );
    expect(prepared.endpoint).toBe(
      "https://example.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21",
    );
  });

  test("Grok delegates to the OpenAI-compatible shape and accepts the xai alias", () => {
    const prepared = new GrokAdapter().prepareChatCompletions(
      { name: "xai", kind: "xai", baseUrl: "https://api.x.ai/v1/", apiKey: "s" },
      { logicalModel: "grok-chat", providerModel: "grok-4.20-fast", stream: false, body: { messages: [] } },
    );
    expect(prepared.endpoint).toBe("https://api.x.ai/v1/chat/completions");
    expect((prepared.body as Record<string, unknown>)["model"]).toBe("grok-4.20-fast");
  });

  test("OpenRouter injects attribution headers and strips stream_options", () => {
    const prepared = new OpenRouterAdapter().prepareChatCompletions(
      {
        name: "openrouter",
        kind: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1/",
        apiKey: "s",
        openrouterHttpReferer: "https://ferrogate.example",
        openrouterXTitle: "FerroGate",
      },
      { logicalModel: "router", providerModel: "openai/gpt-4o-mini", stream: true, body: { messages: [] } },
    );
    expect((prepared.body as Record<string, unknown>)["stream_options"]).toBeUndefined();
    expect(headerValue(prepared.headers, "http-referer")).toBe("https://ferrogate.example");
    expect(headerValue(prepared.headers, "x-title")).toBe("FerroGate");
  });
});

describe("Gemini", () => {
  const provider = (apiKey?: string): ProviderConfig => ({
    name: "gemini",
    kind: "gemini",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/",
    apiKey,
  });

  test("chat plan → generateContent with system instruction + generationConfig", () => {
    const prepared = new GeminiAdapter().prepareChatCompletions(provider("s"), {
      logicalModel: "flash",
      providerModel: "gemini-2.5-flash",
      stream: false,
      body: {
        messages: [
          { role: "system", content: "be concise" },
          { role: "user", content: "hello" },
        ],
        max_tokens: 256,
        top_p: 0.8,
        stop: ["END"],
      },
    });
    expect(prepared.endpoint).toBe(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
    );
    const body = prepared.body as any;
    expect(body.contents[0].parts[0].text).toBe("hello");
    expect(body.systemInstruction.parts[0].text).toBe("be concise");
    expect(body.generationConfig.maxOutputTokens).toBe(256);
    expect(body.generationConfig.stopSequences[0]).toBe("END");
  });

  test("streaming uses the SSE streamGenerateContent endpoint", () => {
    const prepared = new GeminiAdapter().prepareChatCompletions(provider(), {
      logicalModel: "flash",
      providerModel: "models/gemini-2.5-flash",
      stream: true,
      body: { messages: [{ role: "user", content: "hello" }] },
    });
    expect(prepared.endpoint).toBe(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
    );
  });

  test("embeddings → batchEmbedContents and normalizes to OpenAI shape", () => {
    const adapter = new GeminiAdapter();
    const prepared = adapter.prepareEmbeddings(provider(), {
      logicalModel: "flash-embed",
      providerModel: "text-embedding-004",
      body: { input: ["alpha", "beta"] },
    });
    expect(prepared.endpoint).toBe(
      "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:batchEmbedContents",
    );
    const normalized = adapter.translateEmbeddingsResponse(
      bytes('{"embeddings":[{"values":[0.1,0.2,0.3]},{"values":[0.4,0.5,0.6]}]}'),
      "flash-embed",
    ) as any;
    expect(normalized.object).toBe("list");
    expect(normalized.data[1].index).toBe(1);
    expect(normalized.data[1].embedding[0]).toBe(0.4);
    expect(normalized.usage).toBeUndefined();
  });

  test("rejects pre-tokenized embeddings input (edge case)", () => {
    expect(() =>
      new GeminiAdapter().prepareEmbeddings(provider(), {
        logicalModel: "e",
        providerModel: "text-embedding-004",
        body: { input: [1, 2, 3] },
      }),
    ).toThrowError(/string or string-array input only/);
  });
});

describe("Bedrock + Vertex (credentialed)", () => {
  test("Bedrock signs a Converse request and hides the secret key", () => {
    const prepared = new BedrockAdapter().prepareChatCompletions(
      {
        name: "bedrock",
        kind: "bedrock",
        baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
        awsCredentials: {
          accessKeyId: "AKIDEXAMPLE",
          secretAccessKey: new SecretValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
          region: "us-east-1",
        },
      },
      {
        logicalModel: "chat",
        providerModel: "anthropic.claude-3-5-sonnet-20241022-v2:0",
        stream: false,
        body: { messages: [{ role: "system", content: "be concise" }, { role: "user", content: "hello" }], max_tokens: 256 },
      },
    );
    expect(prepared.endpoint).toBe(
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
    );
    const body = prepared.body as any;
    expect(body.messages[0].content[0].text).toBe("hello");
    expect(body.system[0].text).toBe("be concise");
    expect(body.inferenceConfig.maxTokens).toBe(256);
    expect(headerValue(prepared.headers, "authorization")).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//);
    expect(JSON.stringify(prepared)).not.toContain("wJalrXUtnFEMI");
  });

  test("Bedrock fails closed without AWS credentials (edge case)", () => {
    expect(() =>
      new BedrockAdapter().prepareChatCompletions(
        { name: "b", kind: "bedrock", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com" },
        { logicalModel: "c", providerModel: "m", stream: false, body: { messages: [] } },
      ),
    ).toThrowError(/missing AWS credentials/);
  });

  test("Vertex builds the projects/locations endpoint and meters predict tokens", () => {
    const provider: ProviderConfig = {
      name: "vertex",
      kind: "vertex",
      baseUrl: "https://us-central1-aiplatform.googleapis.com",
      gcpCredentials: {
        accessToken: new SecretValue("ya29.EXAMPLE"),
        projectId: "my-gcp-project",
        location: "us-central1",
      },
    };
    const adapter = new VertexAiAdapter();
    const prepared = adapter.prepareChatCompletions(provider, {
      logicalModel: "vertex-chat",
      providerModel: "gemini-1.5-pro",
      stream: false,
      body: { messages: [{ role: "user", content: "hello" }] },
    });
    expect(prepared.endpoint).toBe(
      "https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
    );
    expect(headerValue(prepared.headers, "authorization")).toBe("Bearer ya29.EXAMPLE");

    const raw = bytes('{"predictions":[{"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":3}}},{"embeddings":{"values":[0.3,0.4],"statistics":{"token_count":4}}}]}');
    const normalized = adapter.translateEmbeddingsResponse(raw, "vertex-embed") as any;
    expect(normalized.usage.prompt_tokens).toBe(7);
    expect(adapter.extractUsage(raw)).toEqual({ promptTokens: 7, completionTokens: undefined, totalTokens: 7 });
  });
});
