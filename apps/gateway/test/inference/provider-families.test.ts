/**
 * The three OpenAI-compatible-on-the-wire provider families —
 * `grok.rs`, `openrouter.rs`, `azure.rs`.
 *
 * These were previously resolved to `null` by `defaultAdapterRegistry` and
 * answered `unsupported provider kind`. Aliasing them onto the plain OpenAI
 * adapter would have been wrong, and every assertion below is a place where it
 * would have been wrong: OpenRouter must DELETE the `stream_options` the OpenAI
 * adapter injects, and Azure must delete `model` from the body, address a
 * deployment in the path, and authenticate with `api-key`.
 *
 * Driven through the real router + adapter + dispatch path; only the outbound
 * provider `fetch` is stubbed.
 */
import { describe, expect, it } from "vitest";
import {
  encodeAzurePathSegment,
  splitAzureBaseUrl,
} from "../../src/inference/index.js";
import type { OpenRouterRoute, PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson, providerSse } from "./provider-mock.js";

const GROK_ROUTE: PhysicalRoute = {
  logicalModel: "grok-chat",
  provider: "xai",
  providerModel: "grok-4.20-fast",
  providerKind: "grok",
  baseUrl: "https://api.x.ai/v1/",
  apiKey: "provider-secret",
  enabled: true,
};

const XAI_ALIAS_ROUTE: PhysicalRoute = {
  ...GROK_ROUTE,
  logicalModel: "grok-alias",
  providerKind: "xai",
};

const OPENROUTER_ROUTE: OpenRouterRoute = {
  logicalModel: "router-chat",
  provider: "openrouter",
  providerModel: "openai/gpt-4o-mini",
  providerKind: "openrouter",
  baseUrl: "https://openrouter.ai/api/v1/",
  apiKey: "provider-secret",
  enabled: true,
  openrouterHttpReferer: "https://ferrogate.example",
  openrouterXTitle: "FerroGate",
};

/** Same family, no attribution configured — the headers must simply be absent. */
const OPENROUTER_BARE_ROUTE: OpenRouterRoute = {
  ...OPENROUTER_ROUTE,
  logicalModel: "router-bare",
  openrouterHttpReferer: undefined,
  openrouterXTitle: undefined,
};

const AZURE_ROUTE: PhysicalRoute = {
  logicalModel: "fast-chat",
  provider: "azure-eastus",
  // A space, so `encode_path_segment` is actually exercised.
  providerModel: "gpt-4o mini",
  providerKind: "azure-openai",
  baseUrl: "https://example.openai.azure.com/?api-version=2024-02-15-preview",
  apiKey: "provider-secret",
  // Set deliberately: Azure must IGNORE it and still write `api-key`.
  authScheme: "bearer",
  enabled: true,
};

const AZURE_NO_VERSION_ROUTE: PhysicalRoute = {
  ...AZURE_ROUTE,
  logicalModel: "fast-chat-default-version",
  providerModel: "gpt-4o-mini",
  baseUrl: "https://example.openai.azure.com/",
};

const ROUTES: readonly (PhysicalRoute | OpenRouterRoute)[] = [
  GROK_ROUTE,
  XAI_ALIAS_ROUTE,
  OPENROUTER_ROUTE,
  OPENROUTER_BARE_ROUTE,
  AZURE_ROUTE,
  AZURE_NO_VERSION_ROUTE,
];

function family(): ReturnType<typeof harness> {
  return harness({}, ROUTES);
}

const COMPLETION = {
  id: "chatcmpl-1",
  choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
  usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
};

describe("grok / xai", () => {
  it("dispatches chat completions as an OpenAI-compatible request", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "grok-chat",
        messages: [{ role: "user", content: "hello" }],
        stream: false,
      });

      expect(res.status).toBe(200);
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://api.x.ai/v1/chat/completions");
      expect(upstream.headers["authorization"]).toBe("Bearer provider-secret");
      // The adapter owns `model`: the LOGICAL name must not reach xAI.
      expect((upstream.body as { model: string }).model).toBe("grok-4.20-fast");
    } finally {
      provider.restore();
    }
  });

  it("accepts the `xai` provider-kind alias", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "grok-alias",
        messages: [{ role: "user", content: "hello" }],
      });

      expect(res.status).toBe(200);
      expect((provider.lastRequest().body as { model: string }).model).toBe("grok-4.20-fast");
    } finally {
      provider.restore();
    }
  });

  it("serves /v1/responses", async () => {
    const provider = interceptProviderFetch(() => providerJson({ id: "resp_1" }));
    try {
      const res = await family().post("/v1/responses", {
        model: "grok-chat",
        input: "hello",
      });

      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toBe("https://api.x.ai/v1/responses");
    } finally {
      provider.restore();
    }
  });

  it("refuses embeddings with the trait default, not a silent OpenAI call", async () => {
    let called = false;
    const provider = interceptProviderFetch(() => {
      called = true;
      return providerJson({});
    });
    try {
      const res = await family().post("/v1/embeddings", { model: "grok-chat", input: "hi" });

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe("unsupported provider kind grok");
      expect(called).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("refuses images as an unsupported CAPABILITY (issue #275)", async () => {
    const provider = interceptProviderFetch(() => providerJson({}));
    try {
      const res = await family().post("/v1/images/generations", {
        model: "grok-chat",
        prompt: "a cat",
      });

      expect((await errorBody(res)).error.message).toBe(
        "provider kind grok does not support image generation",
      );
    } finally {
      provider.restore();
    }
  });
});

describe("openrouter", () => {
  it("adds the attribution headers and keeps the OpenAI wire shape", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "router-chat",
        messages: [{ role: "user", content: "hello" }],
      });

      expect(res.status).toBe(200);
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://openrouter.ai/api/v1/chat/completions");
      expect(upstream.headers["authorization"]).toBe("Bearer provider-secret");
      expect(upstream.headers["http-referer"]).toBe("https://ferrogate.example");
      expect(upstream.headers["x-title"]).toBe("FerroGate");
      expect((upstream.body as { model: string }).model).toBe("openai/gpt-4o-mini");
    } finally {
      provider.restore();
    }
  });

  it("omits the attribution headers when the provider configures none", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      await family().post("/v1/chat/completions", {
        model: "router-bare",
        messages: [{ role: "user", content: "hello" }],
      });

      const upstream = provider.lastRequest();
      expect(upstream.headers["http-referer"]).toBeUndefined();
      expect(upstream.headers["x-title"]).toBeUndefined();
    } finally {
      provider.restore();
    }
  });

  it("STRIPS `stream_options` on a stream — OpenRouter deprecated the opt-in", async () => {
    const provider = interceptProviderFetch(() =>
      providerSse(['data: {"choices":[{"delta":{"content":"hi"}}]}\n\n', "data: [DONE]\n\n"]),
    );
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "router-chat",
        messages: [{ role: "user", content: "hello" }],
        stream: true,
      });
      await res.text();

      const body = provider.lastRequest().body as Record<string, unknown>;
      expect(body["stream"]).toBe(true);
      // The OpenAI adapter injects this; OpenRouter must take it back off, or
      // the upstream sees a flag it has deprecated.
      expect("stream_options" in body).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("keeps `stream_options` off the NON-streaming body too (it was never added)", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      await family().post("/v1/chat/completions", {
        model: "router-chat",
        messages: [{ role: "user", content: "hello" }],
      });

      expect("stream_options" in (provider.lastRequest().body as object)).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("refuses images as an unsupported capability", async () => {
    const provider = interceptProviderFetch(() => providerJson({}));
    try {
      const res = await family().post("/v1/images/generations", {
        model: "router-chat",
        prompt: "a cat",
      });

      expect((await errorBody(res)).error.message).toBe(
        "provider kind openrouter does not support image generation",
      );
    } finally {
      provider.restore();
    }
  });
});

describe("azure-openai", () => {
  it("addresses the DEPLOYMENT in the path and drops `model` from the body", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "fast-chat",
        messages: [{ role: "user", content: "hello" }],
        temperature: 0.2,
      });

      expect(res.status).toBe(200);
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe(
        "https://example.openai.azure.com/openai/deployments/gpt-4o%20mini/chat/completions?api-version=2024-02-15-preview",
      );
      const body = upstream.body as Record<string, unknown>;
      // Azure rejects a body carrying `model`; the deployment IS the model.
      expect("model" in body).toBe(false);
      expect(body["stream"]).toBe(false);
      expect(body["temperature"]).toBe(0.2);
    } finally {
      provider.restore();
    }
  });

  it("authenticates with `api-key`, ignoring the route's auth_scheme", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      await family().post("/v1/chat/completions", {
        model: "fast-chat",
        messages: [{ role: "user", content: "hello" }],
      });

      const upstream = provider.lastRequest();
      expect(upstream.headers["api-key"]).toBe("provider-secret");
      // `authScheme: "bearer"` is set on the route on purpose; Azure's scheme is
      // a property of Azure, exactly as in the Rust adapter.
      expect(upstream.headers["authorization"]).toBeUndefined();
    } finally {
      provider.restore();
    }
  });

  it("falls back to the default api-version when the base_url carries none", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      await family().post("/v1/chat/completions", {
        model: "fast-chat-default-version",
        messages: [{ role: "user", content: "hello" }],
      });

      expect(provider.lastRequest().url).toBe(
        "https://example.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21",
      );
    } finally {
      provider.restore();
    }
  });

  it("asks for streaming usage on a stream", async () => {
    const provider = interceptProviderFetch(() =>
      providerSse(['data: {"choices":[{"delta":{"content":"hi"}}]}\n\n', "data: [DONE]\n\n"]),
    );
    try {
      const res = await family().post("/v1/chat/completions", {
        model: "fast-chat",
        messages: [{ role: "user", content: "hello" }],
        stream: true,
      });
      await res.text();

      const body = provider.lastRequest().body as {
        stream: boolean;
        stream_options: { include_usage: boolean };
      };
      expect(body.stream).toBe(true);
      expect(body.stream_options.include_usage).toBe(true);
    } finally {
      provider.restore();
    }
  });

  it("refuses /v1/responses — Azure only overrides prepare_chat_completions", async () => {
    let called = false;
    const provider = interceptProviderFetch(() => {
      called = true;
      return providerJson({});
    });
    try {
      const res = await family().post("/v1/responses", { model: "fast-chat", input: "hi" });

      expect((await errorBody(res)).error.message).toBe(
        "unsupported provider kind azure-openai",
      );
      expect(called).toBe(false);
    } finally {
      provider.restore();
    }
  });
});

describe("azure base_url / path-segment helpers", () => {
  it("splits the api-version out of the base_url query", () => {
    expect(splitAzureBaseUrl("https://x.openai.azure.com/?api-version=2024-02-15-preview")).toEqual(
      { endpoint: "https://x.openai.azure.com/", apiVersion: "2024-02-15-preview" },
    );
  });

  it("defaults the api-version when the query has none, or an empty one", () => {
    expect(splitAzureBaseUrl("https://x.openai.azure.com/")).toEqual({
      endpoint: "https://x.openai.azure.com/",
      apiVersion: "2024-10-21",
    });
    expect(splitAzureBaseUrl("https://x.openai.azure.com/?api-version=")).toEqual({
      endpoint: "https://x.openai.azure.com/",
      apiVersion: "2024-10-21",
    });
    expect(splitAzureBaseUrl("https://x.openai.azure.com/?other=1")).toEqual({
      endpoint: "https://x.openai.azure.com/",
      apiVersion: "2024-10-21",
    });
  });

  it("percent-encodes everything outside the unreserved set", () => {
    // `encodeURIComponent` leaves `!'()*` alone, which would put different bytes
    // on the wire than the Rust `encode_path_segment`.
    expect(encodeAzurePathSegment("gpt-4o mini")).toBe("gpt-4o%20mini");
    expect(encodeAzurePathSegment("a/b")).toBe("a%2Fb");
    expect(encodeAzurePathSegment("it's(1)*")).toBe("it%27s%281%29%2A");
    expect(encodeAzurePathSegment("keep-._~")).toBe("keep-._~");
  });
});
