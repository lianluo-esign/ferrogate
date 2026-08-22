import type { SeedProviderChannel } from "@ferrogate/storage";
import { describe, expect, it } from "vitest";
import {
  listProviderConnectivityModels,
  testProviderConnectivity,
} from "../src/store/platform-provider-connectivity.js";

function provider(overrides: Partial<SeedProviderChannel> = {}): SeedProviderChannel {
  return {
    id: "provider-openai",
    name: "openai-main",
    kind: "openai-compatible",
    base_url: "https://upstream.test/v1",
    api_key_var: "OPENAI_KEY",
    byok_alias: null,
    auth_scheme: null,
    region: null,
    zero_data_retention: null,
    openrouter_http_referer: null,
    openrouter_x_title: null,
    cloudflare_ai_gateway_json: null,
    enabled: 1,
    ...overrides,
  };
}

describe("platform provider connectivity", () => {
  it("loads and sorts the provider's live model ids", async () => {
    const calls: Array<{ url: string; authorization: string | null }> = [];
    const models = await listProviderConnectivityModels({
      provider: provider(),
      apiKey: "sk-live",
      fetchImpl: async (input, init) => {
        const headers = new Headers(init?.headers);
        calls.push({ url: String(input), authorization: headers.get("authorization") });
        return Response.json({ data: [{ id: "gpt-z" }, { id: "gpt-a" }, { id: "gpt-z" }] });
      },
    });

    expect(models).toEqual(["gpt-a", "gpt-z"]);
    expect(calls).toEqual([
      { url: "https://upstream.test/v1/models", authorization: "Bearer sk-live" },
    ]);
  });

  it("bounds the live model response before parsing it", async () => {
    await expect(
      listProviderConnectivityModels({
        provider: provider(),
        apiKey: "sk-live",
        fetchImpl: async () =>
          new Response("", { headers: { "content-length": String(1_048_577) } }),
      }),
    ).rejects.toMatchObject({
      code: "provider_unreachable",
      status: 502,
    });
  });

  it("sends hi through the gateway adapter for the selected model", async () => {
    const calls: Array<{ url: string; body: unknown; authorization: string | null }> = [];
    const clock = [100, 137];
    const result = await testProviderConnectivity({
      provider: provider(),
      apiKey: "sk-live",
      model: "gpt-5.4",
      protocol: "chat.completions",
      now: () => clock.shift() ?? 137,
      fetchImpl: async (input, init) => {
        const headers = new Headers(init?.headers);
        calls.push({
          url: String(input),
          body: JSON.parse(String(init?.body)),
          authorization: headers.get("authorization"),
        });
        return Response.json({
          id: "chatcmpl-test",
          object: "chat.completion",
          choices: [
            { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
          ],
        });
      },
    });

    expect(calls).toEqual([
      {
        url: "https://upstream.test/v1/chat/completions",
        authorization: "Bearer sk-live",
        body: {
          model: "gpt-5.4",
          messages: [{ role: "user", content: "hi" }],
          stream: false,
        },
      },
    ]);
    expect(result).toMatchObject({
      model: "gpt-5.4",
      protocol: "chat.completions",
      latencyMs: 37,
      status: 200,
      answer: "hi",
    });
  });

  it("sends hi through the Responses API and extracts the answer", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const result = await testProviderConnectivity({
      provider: provider(),
      apiKey: "sk-live",
      model: "gpt-5.5",
      protocol: "responses",
      fetchImpl: async (input, init) => {
        calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
        return Response.json({
          id: "resp-test",
          object: "response",
          output: [
            {
              type: "message",
              role: "assistant",
              content: [{ type: "output_text", text: "Hello from Responses" }],
            },
          ],
        });
      },
    });

    expect(calls).toEqual([
      {
        url: "https://upstream.test/v1/responses",
        body: {
          model: "gpt-5.5",
          input: "hi",
          stream: false,
        },
      },
    ]);
    expect(result).toMatchObject({
      model: "gpt-5.5",
      protocol: "responses",
      status: 200,
      answer: "Hello from Responses",
    });
  });

  it("uses the Anthropic adapter and never returns an upstream error body", async () => {
    let requestUrl = "";
    let apiKey = "";
    await expect(
      testProviderConnectivity({
        provider: provider({ kind: "anthropic", auth_scheme: "x-api-key" }),
        apiKey: "anthropic-secret",
        model: "claude-sonnet",
        protocol: "chat.completions",
        fetchImpl: async (input, init) => {
          requestUrl = String(input);
          apiKey = new Headers(init?.headers).get("x-api-key") ?? "";
          return Response.json(
            { error: { message: "sensitive upstream detail" } },
            { status: 401 },
          );
        },
      }),
    ).rejects.toMatchObject({
      code: "provider_test_failed",
      status: 502,
      message: "upstream returned HTTP 401",
    });
    expect(requestUrl).toBe("https://upstream.test/v1/messages");
    expect(apiKey).toBe("anthropic-secret");
  });
});
