/**
 * The two families that used to resolve to `null` — `bedrock` and `vertex`.
 *
 * They were unreachable not because of the Cloudflare platform but because
 * `PhysicalRoute` had nowhere to put a COMPOSITE credential: SigV4 needs an
 * access-key id + secret + optional session token + region, and Vertex needs a
 * pre-minted OAuth2 token + project + location, while every other family
 * authenticates with one opaque `apiKey` string. `ports.ts` now carries
 * `awsCredentials`/`gcpCredentials`, `catalog.ts` resolves them from the Rust
 * config's `aws_*`/`gcp_*` provider fields (with `_env` → `_var`, because a
 * Worker names a SECRET BINDING), and `defaultAdapterRegistry` wraps
 * `@ferrogate/providers`' `BedrockAdapter` / `VertexAiAdapter`.
 *
 * Everything below is driven through the REAL router → registry → adapter →
 * dispatch path; only the outbound provider `fetch` is intercepted. The
 * assertions are on the bytes that would have gone on the wire, which is the
 * only place a credential bug is observable.
 */
import { describe, expect, it } from "vitest";
import {
  buildModelCatalog,
  defaultAdapterRegistry,
  modelCatalogFromEnv,
} from "../../src/inference/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const BEDROCK_ROUTE: PhysicalRoute = {
  logicalModel: "bedrock-chat",
  provider: "aws-main",
  // A colon, so the adapter's percent-encoding of the path segment is exercised.
  providerModel: "anthropic.claude-3-5-sonnet-20241022-v2:0",
  providerKind: "bedrock",
  baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
  enabled: true,
  awsCredentials: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
  },
};

/** Same provider reached through the Rust alias `aws-bedrock`. */
const BEDROCK_ALIAS_ROUTE: PhysicalRoute = {
  ...BEDROCK_ROUTE,
  logicalModel: "bedrock-alias",
  providerKind: "aws-bedrock",
};

/** STS/assumed-role credentials — the session token becomes its own header. */
const BEDROCK_STS_ROUTE: PhysicalRoute = {
  ...BEDROCK_ROUTE,
  logicalModel: "bedrock-sts",
  awsCredentials: {
    ...(BEDROCK_ROUTE.awsCredentials as NonNullable<typeof BEDROCK_ROUTE.awsCredentials>),
    sessionToken: "FQoGZXIvYXdzEXAMPLE",
  },
};

/**
 * A Bedrock route with NO credential. Reachable only by hand-building a route
 * (the catalog refuses such a provider outright) and pinned because it is the
 * fail-closed boundary: an unsigned Bedrock request must never be dispatched.
 */
const BEDROCK_UNSIGNED_ROUTE: PhysicalRoute = {
  logicalModel: "bedrock-unsigned",
  provider: "aws-broken",
  providerModel: "amazon.titan-text-express-v1",
  providerKind: "bedrock",
  baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
  enabled: true,
};

const BEDROCK_EMBEDDINGS_ROUTE: PhysicalRoute = {
  ...BEDROCK_ROUTE,
  logicalModel: "bedrock-embed",
  providerModel: "amazon.titan-embed-text-v2:0",
};

const VERTEX_ROUTE: PhysicalRoute = {
  logicalModel: "vertex-chat",
  provider: "gcp-main",
  providerModel: "gemini-1.5-pro",
  providerKind: "vertex",
  baseUrl: "https://us-central1-aiplatform.googleapis.com",
  enabled: true,
  gcpCredentials: {
    accessToken: "ya29.EXAMPLE-ACCESS-TOKEN",
    projectId: "ferrogate-prod",
    location: "us-central1",
  },
};

const VERTEX_ALIAS_ROUTE: PhysicalRoute = {
  ...VERTEX_ROUTE,
  logicalModel: "vertex-alias",
  providerKind: "vertex-ai",
};

const VERTEX_UNAUTHENTICATED_ROUTE: PhysicalRoute = {
  logicalModel: "vertex-unauthenticated",
  provider: "gcp-broken",
  providerModel: "gemini-1.5-flash",
  providerKind: "vertex",
  baseUrl: "https://us-central1-aiplatform.googleapis.com",
  enabled: true,
};

const ROUTES: readonly PhysicalRoute[] = [
  BEDROCK_ROUTE,
  BEDROCK_ALIAS_ROUTE,
  BEDROCK_STS_ROUTE,
  BEDROCK_UNSIGNED_ROUTE,
  BEDROCK_EMBEDDINGS_ROUTE,
  VERTEX_ROUTE,
  VERTEX_ALIAS_ROUTE,
  VERTEX_UNAUTHENTICATED_ROUTE,
];

const CHAT = { messages: [{ role: "user", content: "hi" }] };

/**
 * MOUNTING GUARD. `defaultAdapterRegistry` is the registry every composition
 * root gets; an adapter that exists but is not in this switch is dead code that
 * every direct-construction test would still pass. Asserting on the SHIPPED
 * registry (not on a locally-built one) is what makes that failure visible.
 */
describe("defaultAdapterRegistry resolves both families", () => {
  it.each([
    ["bedrock", "bedrock"],
    ["aws-bedrock", "bedrock"],
    ["vertex", "vertex"],
    ["vertex-ai", "vertex"],
  ])("%s → the %s adapter", (spelling, canonical) => {
    const adapter = defaultAdapterRegistry.adapterFor(spelling);
    expect(adapter).not.toBeNull();
    expect(adapter?.kind).toBe(canonical);
  });

  it("still refuses a family that does not exist", () => {
    expect(defaultAdapterRegistry.adapterFor("not-a-provider")).toBeNull();
  });
});

describe("bedrock chat completions", () => {
  it("signs the Converse request with SigV4 and translates the body", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({
        output: { message: { role: "assistant", content: [{ text: "hello" }] } },
        stopReason: "end_turn",
        usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "bedrock-chat",
        ...CHAT,
      });
      expect(response.status).toBe(200);

      const sent = intercept.lastRequest();
      // `/converse` for BOTH streaming and non-streaming — `bedrock.rs` uses
      // one path and one signing helper (issue #274), so the port does too.
      expect(sent.url).toBe(
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/" +
          "anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
      );
      // The credential reached the wire as a SIGNATURE, never as a bearer token.
      expect(sent.headers.authorization).toMatch(
        /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/\d{8}\/us-east-1\/bedrock\/aws4_request, SignedHeaders=[^,]+, Signature=[0-9a-f]{64}$/,
      );
      expect(sent.headers["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
      // No session token configured ⇒ the header must be absent entirely.
      expect(sent.headers["x-amz-security-token"]).toBeUndefined();
      // The secret itself is never a header value.
      expect(JSON.stringify(sent.headers)).not.toContain(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      );
      // OpenAI `messages` became Bedrock `messages` with content BLOCKS.
      expect(sent.body).toEqual({
        messages: [{ role: "user", content: [{ text: "hi" }] }],
      });
    } finally {
      intercept.restore();
    }
  });

  it("meters the call from the Converse usage envelope (camelCase)", async () => {
    // The regression lock for the zero-billing bug: `usageProviderKindFor` had
    // no `bedrock` arm, so Converse's camelCase `inputTokens`/`outputTokens`
    // fell through to the OpenAI extractor (which reads snake_case), scraped
    // nothing, and metered the call at $0. See `inference/usage.ts`.
    const intercept = interceptProviderFetch(() =>
      providerJson({
        output: { message: { role: "assistant", content: [{ text: "hello" }] } },
        stopReason: "end_turn",
        usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", { model: "bedrock-chat", ...CHAT });
      expect(h.usage.last?.promptTokens).toBe(3);
      expect(h.usage.last?.completionTokens).toBe(2);
      expect(h.usage.last?.totalTokens).toBe(5);
    } finally {
      intercept.restore();
    }
  });

  it("meters embeddings from `inputTextTokenCount`", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({ embedding: [0.5, 0.25], inputTextTokenCount: 4 }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/embeddings", { model: "bedrock-embed", input: "hello" });
      expect(h.usage.last?.promptTokens).toBe(4);
      expect(h.usage.last?.totalTokens).toBe(4);
    } finally {
      intercept.restore();
    }
  });

  it("the `aws-bedrock` alias reaches the same adapter", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({ output: { message: { role: "assistant", content: [{ text: "ok" }] } } }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "bedrock-alias",
        ...CHAT,
      });
      expect(response.status).toBe(200);
      expect(intercept.lastRequest().headers.authorization).toContain("AWS4-HMAC-SHA256");
    } finally {
      intercept.restore();
    }
  });

  it("an STS session token is sent as `x-amz-security-token`", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({ output: { message: { role: "assistant", content: [{ text: "ok" }] } } }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", { model: "bedrock-sts", ...CHAT });
      expect(intercept.lastRequest().headers["x-amz-security-token"]).toBe("FQoGZXIvYXdzEXAMPLE");
    } finally {
      intercept.restore();
    }
  });

  it("a route with no AWS credential is refused before any request is made", async () => {
    const intercept = interceptProviderFetch(() => providerJson({ never: "reached" }));
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "bedrock-unsigned",
        ...CHAT,
      });
      expect(response.status).toBe(400);
      const body = await errorBody(response);
      expect(body.error.code).toBe("invalid_request");
      expect(body.error.message).toContain("bedrock provider is missing AWS credentials");
      // The whole point: nothing was dispatched unsigned.
      expect(intercept.requests).toHaveLength(0);
    } finally {
      intercept.restore();
    }
  });

  it("embeddings go to `/invoke` and come back OpenAI-shaped", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({ embedding: [0.5, 0.25], inputTextTokenCount: 4 }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/embeddings", {
        model: "bedrock-embed",
        input: "hello",
      });
      expect(response.status).toBe(200);
      expect(intercept.lastRequest().url).toBe(
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/" +
          "amazon.titan-embed-text-v2%3A0/invoke",
      );
      expect(intercept.lastRequest().body).toEqual({ inputText: "hello" });
      const payload = (await response.json()) as {
        object: string;
        data: { embedding: number[] }[];
      };
      expect(payload.object).toBe("list");
      expect(payload.data[0]?.embedding).toEqual([0.5, 0.25]);
    } finally {
      intercept.restore();
    }
  });
});

describe("vertex chat completions", () => {
  it("addresses project/location and authenticates with the pre-minted token", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({
        candidates: [{ content: { role: "model", parts: [{ text: "hello" }] } }],
        usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2, totalTokenCount: 5 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "vertex-chat",
        ...CHAT,
      });
      expect(response.status).toBe(200);

      const sent = intercept.lastRequest();
      expect(sent.url).toBe(
        "https://us-central1-aiplatform.googleapis.com/v1/projects/ferrogate-prod/" +
          "locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
      );
      expect(sent.headers.authorization).toBe("Bearer ya29.EXAMPLE-ACCESS-TOKEN");
      expect(sent.body).toEqual({
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      });
    } finally {
      intercept.restore();
    }
  });

  it("meters the call from Vertex's `usageMetadata` (Gemini-shaped)", async () => {
    // Vertex serves Gemini-shaped bodies, so it must reuse the Gemini extractor.
    // With no `vertex` arm it fell through to OpenAI and metered $0.
    const intercept = interceptProviderFetch(() =>
      providerJson({
        candidates: [{ content: { role: "model", parts: [{ text: "hello" }] } }],
        usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2, totalTokenCount: 5 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", { model: "vertex-chat", ...CHAT });
      expect(h.usage.last?.promptTokens).toBe(3);
      expect(h.usage.last?.completionTokens).toBe(2);
      expect(h.usage.last?.totalTokens).toBe(5);
    } finally {
      intercept.restore();
    }
  });

  it("a streaming request switches to `streamGenerateContent?alt=sse`", async () => {
    const intercept = interceptProviderFetch(
      () =>
        new Response('data: {"candidates":[]}\n\n', {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "vertex-chat",
        stream: true,
        ...CHAT,
      });
      expect(response.status).toBe(200);
      await response.text();
      expect(intercept.lastRequest().url).toBe(
        "https://us-central1-aiplatform.googleapis.com/v1/projects/ferrogate-prod/" +
          "locations/us-central1/publishers/google/models/gemini-1.5-pro:streamGenerateContent?alt=sse",
      );
    } finally {
      intercept.restore();
    }
  });

  it("the `vertex-ai` alias reaches the same adapter", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({ candidates: [{ content: { role: "model", parts: [{ text: "ok" }] } }] }),
    );
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "vertex-alias",
        ...CHAT,
      });
      expect(response.status).toBe(200);
      expect(intercept.lastRequest().headers.authorization).toBe(
        "Bearer ya29.EXAMPLE-ACCESS-TOKEN",
      );
    } finally {
      intercept.restore();
    }
  });

  it("a route with no GCP credential is refused before any request is made", async () => {
    const intercept = interceptProviderFetch(() => providerJson({ never: "reached" }));
    try {
      const h = harness({}, ROUTES);
      const response = await h.post("/v1/chat/completions", {
        model: "vertex-unauthenticated",
        ...CHAT,
      });
      expect(response.status).toBe(400);
      const body = await errorBody(response);
      expect(body.error.message).toContain("vertex provider is missing GCP credentials");
      expect(intercept.requests).toHaveLength(0);
    } finally {
      intercept.restore();
    }
  });
});

/**
 * The config half: `aws_*` / `gcp_*` on the provider table, resolved out of the
 * Worker SECRET bindings. This is the port of the Rust config validator's
 * Bedrock/Vertex blocks — a misconfigured provider must refuse the WHOLE
 * catalog (every model then answers `model_not_found`) rather than produce a
 * route that fails later, or worse, one that dispatches unsigned.
 */
describe("catalog: bedrock credentials", () => {
  const provider = {
    name: "aws-main",
    kind: "bedrock",
    base_url: "https://bedrock-runtime.us-east-1.amazonaws.com",
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key_var: "AWS_SECRET",
    region: "us-east-1",
  };
  const model = {
    name: "bedrock-chat",
    provider: "aws-main",
    provider_model: "anthropic.claude-3-5-sonnet-20241022-v2:0",
  };
  const secrets = { AWS_SECRET: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };

  it("builds the composite credential onto the route", () => {
    const result = buildModelCatalog([provider], [model], secrets);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.routes[0]?.awsCredentials).toEqual({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
    });
    // `Provider.region` doubles as `ModelRoute.region` (issue #173) in Rust.
    expect(result.routes[0]?.region).toBe("us-east-1");
  });

  it("an optional session token is resolved when its binding is named", () => {
    const result = buildModelCatalog(
      [{ ...provider, aws_session_token_var: "AWS_SESSION" }],
      [model],
      { ...secrets, AWS_SESSION: "FQoGZXIvYXdzEXAMPLE" },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.routes[0]?.awsCredentials?.sessionToken).toBe("FQoGZXIvYXdzEXAMPLE");
  });

  it.each([
    ["aws_access_key_id", "field providers[0].aws_access_key_id: required when kind = bedrock"],
    [
      "aws_secret_access_key_var",
      "field providers[0].aws_secret_access_key_var: required when kind = bedrock",
    ],
    ["region", "field providers[0].region: required when kind = bedrock"],
  ])("refuses the catalog when %s is missing", (field, reason) => {
    const incomplete: Record<string, unknown> = { ...provider };
    delete incomplete[field];
    const result = buildModelCatalog([incomplete as unknown as typeof provider], [model], secrets);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain(reason);
  });

  it("refuses the catalog when the named secret binding is not bound", () => {
    const result = buildModelCatalog([provider], [model], {});
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(
      "provider aws-main names aws_secret_access_key_var AWS_SECRET, which is not bound",
    );
  });

  it("refuses the catalog when a NAMED session-token binding is not bound", () => {
    const result = buildModelCatalog(
      [{ ...provider, aws_session_token_var: "AWS_SESSION" }],
      [model],
      secrets,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("aws_session_token_var AWS_SESSION, which is not bound");
  });

  it("refuses a misconfigured provider even when NO model references it", () => {
    // Rust validates the provider TABLE, independent of the model table.
    const result = buildModelCatalog(
      [
        { name: "openai", kind: "openai", base_url: "https://api.openai.example/v1" },
        { ...provider, region: undefined },
      ],
      [{ name: "gpt", provider: "openai", provider_model: "gpt-4o-mini" }],
      secrets,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("field providers[1].region: required when kind = bedrock");
  });
});

describe("catalog: vertex credentials", () => {
  const provider = {
    name: "gcp-main",
    kind: "vertex-ai",
    base_url: "https://us-central1-aiplatform.googleapis.com",
    gcp_project_id: "ferrogate-prod",
    gcp_access_token_var: "GCP_TOKEN",
    region: "us-central1",
  };
  const model = {
    name: "vertex-chat",
    provider: "gcp-main",
    provider_model: "gemini-1.5-pro",
  };

  it("builds the composite credential onto the route", () => {
    const result = buildModelCatalog([provider], [model], { GCP_TOKEN: "ya29.TOKEN" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.routes[0]?.gcpCredentials).toEqual({
      accessToken: "ya29.TOKEN",
      projectId: "ferrogate-prod",
      location: "us-central1",
    });
  });

  it.each([
    ["gcp_project_id", "field providers[0].gcp_project_id: required when kind = vertex"],
    [
      "gcp_access_token_var",
      "field providers[0].gcp_access_token_var: required when kind = vertex",
    ],
    ["region", "field providers[0].region: required when kind = vertex"],
  ])("refuses the catalog when %s is missing", (field, reason) => {
    const incomplete: Record<string, unknown> = { ...provider };
    delete incomplete[field];
    const result = buildModelCatalog([incomplete as unknown as typeof provider], [model], {
      GCP_TOKEN: "ya29.TOKEN",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain(reason);
  });

  it("refuses the catalog when the token binding is not bound", () => {
    const result = buildModelCatalog([provider], [model], {});
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(
      "provider gcp-main names gcp_access_token_var GCP_TOKEN, which is not bound",
    );
  });

  it("resolves end-to-end from the Worker vars, credential included", () => {
    const result = modelCatalogFromEnv({
      GATEWAY_PROVIDERS: JSON.stringify([provider]),
      GATEWAY_MODELS: JSON.stringify([model]),
      GCP_TOKEN: "ya29.TOKEN",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.routes[0]?.gcpCredentials?.projectId).toBe("ferrogate-prod");
  });
});

/**
 * A provider table that is not Bedrock/Vertex must not be given credentials it
 * never asked for — carrying them would be dead weight and would make an
 * unrelated family look credential-bearing to anything inspecting the route.
 */
describe("catalog: other families carry no composite credential", () => {
  it("an OpenAI provider gets neither", () => {
    const result = buildModelCatalog(
      [
        {
          name: "openai",
          kind: "openai",
          base_url: "https://api.openai.example/v1",
          api_key_var: "OPENAI_KEY",
        },
      ],
      [{ name: "gpt", provider: "openai", provider_model: "gpt-4o-mini" }],
      { OPENAI_KEY: "sk-test" },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.routes[0]?.awsCredentials).toBeUndefined();
    expect(result.routes[0]?.gcpCredentials).toBeUndefined();
    expect(result.routes[0]?.apiKey).toBe("sk-test");
  });
});
