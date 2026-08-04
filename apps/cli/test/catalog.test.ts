import type { JsonValue } from "@ferrogate/core";
import { describe, expect, test } from "vitest";
import { main } from "../src/index.js";
import type {
  ApiResponse,
  FakeControlPlaneClient,
  RawApiResponse,
  RecordedRequest,
} from "../src/ports.js";
import { createTestRuntime, ok } from "./helpers.js";

function objectBody(value: JsonValue | undefined): Record<string, JsonValue> {
  if (value === undefined || value === null || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, JsonValue>;
}

function listOf(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? [...value] : [];
}

function response(body: JsonValue, status = 200): ApiResponse {
  return { status, body };
}

function createImportClient(): FakeControlPlaneClient {
  const requests: RecordedRequest[] = [];
  const providers: Record<string, JsonValue>[] = [];
  const models: Record<string, JsonValue>[] = [];

  return {
    requests,
    async send(spec, context) {
      requests.push({ spec, context });

      if (spec.method === "GET" && spec.path === "/admin/v1/providers") {
        return response({ object: "list", data: providers });
      }
      if (spec.method === "GET" && spec.path === "/admin/v1/models") {
        return response({ object: "list", data: models });
      }
      if (spec.method === "POST" && spec.path === "/admin/v1/providers") {
        const body = objectBody(spec.body);
        const row = {
          ...body,
          id: body.id ?? body.name ?? `provider-${providers.length + 1}`,
        };
        providers.push(row);
        return response({ object: "provider", provider: row }, 201);
      }
      if (spec.method === "POST" && spec.path === "/admin/v1/models") {
        const body = objectBody(spec.body);
        const row = {
          ...body,
          id: body.id ?? body.name ?? `model-${models.length + 1}`,
          offerings: [],
        };
        models.push(row);
        return response({ object: "model", model: row }, 201);
      }

      const offeringPath = spec.path.match(/^\/admin\/v1\/models\/([^/]+)\/offerings$/);
      if (spec.method === "POST" && offeringPath !== null) {
        const modelId = decodeURIComponent(offeringPath[1] as string);
        const model = models.find((candidate) => candidate.id === modelId);
        if (model === undefined) throw new Error(`unknown model ${modelId}`);
        const body = objectBody(spec.body);
        const offerings = listOf(model.offerings);
        const row = {
          ...body,
          id: body.id ?? `${modelId}-${offerings.length + 1}`,
          model_id: modelId,
        };
        model.offerings = [...offerings, row];
        return response({ object: "offering", offering: row }, 201);
      }

      throw new Error(`unexpected request ${spec.method} ${spec.path}`);
    },
    async sendRaw(spec, mediaType, context): Promise<RawApiResponse> {
      requests.push({ spec, context, mediaType });
      return { status: 200, bytes: new Uint8Array() };
    },
  };
}

const FOUR_OFFERINGS = [
  {
    id: "o-primary",
    provider: "openai",
    upstream_model_id: "gpt-4o",
    role: "primary",
    input_price_per_1m: 0.25,
    output_price_per_1m: 1.5,
  },
  {
    id: "o-fallback",
    provider: "anthropic",
    upstream_model_id: "claude-3-5-sonnet",
    role: "fallback",
    input_price_per_1m: 3,
    output_price_per_1m: 15,
  },
  {
    id: "o-canary",
    provider: "openai",
    upstream_model_id: "gpt-4.1",
    role: "canary",
    input_price_per_1m: 2,
    output_price_per_1m: 8,
  },
  {
    id: "o-shadow",
    provider: "anthropic",
    upstream_model_id: "claude-3-7-sonnet",
    role: "shadow",
    input_price_per_1m: 4,
    output_price_per_1m: 20,
  },
] as const;

function modelShowRuntime(inputPrice: number) {
  const offerings = FOUR_OFFERINGS.map((offering, index) =>
    index === 0 ? { ...offering, input_price_per_1m: inputPrice } : offering,
  );
  return createTestRuntime({
    script: {
      "GET /admin/v1/models/fast": ok({
        object: "model",
        model: {
          id: "fast",
          name: "fast",
          family: "gpt",
          context_window: 128000,
          routing_strategy: "priority",
        },
      }),
      "GET /admin/v1/models/fast/offerings": ok({ object: "list", data: offerings }),
    },
  });
}

describe("provider catalog commands", () => {
  test("provider add sends an Admin API body and renders a table", async () => {
    const runtime = createTestRuntime({
      script: {
        "POST /admin/v1/providers": ok({
          object: "provider",
          provider: { id: "openai", name: "openai", kind: "openai" },
        }),
      },
    });

    expect(
      await main(
        [
          "provider",
          "add",
          "--name",
          "openai",
          "--kind",
          "openai",
          "--base-url",
          "https://api.openai.com/v1",
          "--api-key-var",
          "OPENAI_API_KEY",
          "--auth-scheme",
          "bearer",
          "--region",
          "us",
        ],
        runtime,
      ),
    ).toBe(0);
    expect(runtime.client.requests[0]?.spec.body).toEqual({
      id: "openai",
      name: "openai",
      kind: "openai",
      base_url: "https://api.openai.com/v1",
      api_key_var: "OPENAI_API_KEY",
      auth_scheme: "bearer",
      region: "us",
    });
    expect(runtime.stdout()).toContain("FIELD");
  });

  test("provider list supports the --json shorthand", async () => {
    const body = { object: "list", data: [{ id: "openai", name: "openai", has_api_key: true }] };
    const runtime = createTestRuntime({ script: { "GET /admin/v1/providers": ok(body) } });

    expect(await main(["provider", "list", "--json"], runtime)).toBe(0);
    expect(JSON.parse(runtime.stdout())).toEqual(body);
  });

  test("provider/model CRUD and offering verbs use the Admin API paths", async () => {
    const runtime = createTestRuntime({
      script: {
        "GET /admin/v1/providers/openai": ok({ object: "provider", provider: { id: "openai" } }),
        "PATCH /admin/v1/providers/openai": ok({ object: "provider", provider: { id: "openai" } }),
        "DELETE /admin/v1/providers/openai": ok({ object: "provider", id: "openai", deleted: true }),
        "POST /admin/v1/models": ok({ object: "model", model: { id: "fast" } }),
        "PATCH /admin/v1/models/fast": ok({ object: "model", model: { id: "fast" } }),
        "DELETE /admin/v1/models/fast": ok({ object: "model", id: "fast", deleted: true }),
        "POST /admin/v1/models/fast/offerings": ok({ object: "offering", offering: { id: "o1" } }),
        "GET /admin/v1/models/fast/offerings": ok({ object: "list", data: [{ id: "o1" }] }),
        "GET /admin/v1/models/fast/offerings/o1": ok({ object: "offering", offering: { id: "o1" } }),
        "PATCH /admin/v1/models/fast/offerings/o1": ok({ object: "offering", offering: { id: "o1" } }),
        "DELETE /admin/v1/models/fast/offerings/o1": ok({ object: "offering", id: "o1", deleted: true }),
      },
    });

    expect(await main(["provider", "show", "openai"], runtime)).toBe(0);
    expect(await main(["provider", "update", "openai", "--region", "eu"], runtime)).toBe(0);
    expect(await main(["provider", "rm", "openai"], runtime)).toBe(0);
    expect(
      await main(
        [
          "model",
          "add",
          "--name",
          "fast",
          "--family",
          "gpt",
          "--context-window",
          "128000",
          "--capabilities",
          "chat,streaming,tools",
          "--routing-strategy",
          "priority",
        ],
        runtime,
      ),
    ).toBe(0);
    expect(await main(["model", "update", "fast", "--family", "gpt-4"], runtime)).toBe(0);
    expect(await main(["model", "rm", "fast"], runtime)).toBe(0);
    expect(
      await main(
        [
          "model",
          "offering",
          "add",
          "fast",
          "--provider",
          "openai",
          "--upstream-model",
          "gpt-4o",
          "--role",
          "primary",
          "--input-price",
          "0.25",
          "--output-price",
          "1.5",
        ],
        runtime,
      ),
    ).toBe(0);
    expect(await main(["model", "offering", "ls", "fast"], runtime)).toBe(0);
    expect(await main(["model", "offering", "show", "fast", "o1"], runtime)).toBe(0);
    expect(
      await main(["model", "offering", "update", "fast", "o1", "--input-price", "0.3"], runtime),
    ).toBe(0);
    expect(await main(["model", "offering", "rm", "fast", "o1"], runtime)).toBe(0);

    expect(runtime.client.requests.map(({ spec }) => `${spec.method} ${spec.path}`)).toEqual([
      "GET /admin/v1/providers/openai",
      "PATCH /admin/v1/providers/openai",
      "DELETE /admin/v1/providers/openai",
      "POST /admin/v1/models",
      "PATCH /admin/v1/models/fast",
      "DELETE /admin/v1/models/fast",
      "POST /admin/v1/models/fast/offerings",
      "GET /admin/v1/models/fast/offerings",
      "GET /admin/v1/models/fast/offerings/o1",
      "PATCH /admin/v1/models/fast/offerings/o1",
      "DELETE /admin/v1/models/fast/offerings/o1",
    ]);
  });

  test("a live-looking api-key-var is rejected before any request", async () => {
    const runtime = createTestRuntime();

    const code = await main(
      [
        "provider",
        "add",
        "--name",
        "x",
        "--kind",
        "openai",
        "--base-url",
        "https://x.test",
        "--api-key-var",
        "sk-live-example-key",
      ],
      runtime,
    );

    expect(code).toBe(2);
    expect(runtime.client.requests).toHaveLength(0);
    expect(`${runtime.stdout()}${runtime.stderr()}`).not.toContain("sk-live-example-key");
  });

  test("a server 409 keeps its message and exits non-zero", async () => {
    const runtime = createTestRuntime({
      script: {
        "DELETE /admin/v1/providers/openai": {
          status: 409,
          body: {
            error: {
              code: "catalog_conflict",
              message: "provider openai has live offerings",
            },
          },
        },
      },
    });

    expect(await main(["provider", "rm", "openai"], runtime)).toBe(4);
    expect(runtime.stderr()).toContain("provider openai has live offerings");
  });
});

describe("model show", () => {
  test("combines the model and all offerings in the money table", async () => {
    const runtime = modelShowRuntime(0.25);

    expect(await main(["model", "show", "fast"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("MODEL");
    expect(runtime.stdout()).toContain("primary");
    expect(runtime.stdout()).toContain("fallback");
    expect(runtime.stdout()).toContain("canary");
    expect(runtime.stdout()).toContain("shadow");
    expect(runtime.stdout()).toContain("0.25");
    expect(runtime.stdout()).toContain("20");
    expect(runtime.client.requests.map(({ spec }) => `${spec.method} ${spec.path}`)).toEqual([
      "GET /admin/v1/models/fast",
      "GET /admin/v1/models/fast/offerings",
    ]);
  });

  test("json output round-trips the combined model document", async () => {
    const runtime = modelShowRuntime(0.25);

    expect(await main(["model", "show", "fast", "--json"], runtime)).toBe(0);
    expect(JSON.parse(runtime.stdout())).toEqual({
      id: "fast",
      name: "fast",
      family: "gpt",
      context_window: 128000,
      routing_strategy: "priority",
      offerings: FOUR_OFFERINGS,
    });
  });

  test("the money view moves when an offering price changes", async () => {
    const first = modelShowRuntime(0.25);
    const second = modelShowRuntime(9.25);

    expect(await main(["model", "show", "fast"], first)).toBe(0);
    expect(await main(["model", "show", "fast"], second)).toBe(0);
    expect(first.stdout()).toContain("0.25");
    expect(second.stdout()).toContain("9.25");
    expect(second.stdout()).not.toContain("0.25");
  });
});

describe("provider import", () => {
  test("imports env rows through the API and is idempotent", async () => {
    const client = createImportClient();
    const runtime = createTestRuntime({
      client,
      env: {
        GATEWAY_PROVIDERS: JSON.stringify([
          {
            name: "openai",
            kind: "openai",
            base_url: "https://api.openai.com/v1",
            api_key_var: "OPENAI_API_KEY",
          },
        ]),
        GATEWAY_MODELS: JSON.stringify([
          {
            name: "fast",
            provider: "openai",
            provider_model: "gpt-4o",
            input_price_per_1m: 0.25,
            output_price_per_1m: 1.5,
            fallbacks: [
              {
                provider: "openai",
                provider_model: "gpt-4o-mini",
                input_price_per_1m: 0.15,
                output_price_per_1m: 0.6,
              },
            ],
          },
        ]),
      },
    });

    expect(await main(["provider", "import", "--from-env", "--json"], runtime)).toBe(0);
    const firstCreates = client.requests.filter(({ spec }) => spec.method === "POST").length;
    expect(firstCreates).toBe(4);
    const offeringBodies = client.requests
      .filter(({ spec }) => spec.method === "POST" && spec.path.includes("/offerings"))
      .map(({ spec }) => objectBody(spec.body));
    expect(offeringBodies.map((body) => body.role)).toEqual(["primary", "fallback"]);
    expect(offeringBodies.map((body) => body.provider_id)).toEqual(["openai", "openai"]);
    expect(offeringBodies.map((body) => body.upstream_model_id)).toEqual(["gpt-4o", "gpt-4o-mini"]);
    expect(offeringBodies.map((body) => body.input_price_per_1m)).toEqual([0.25, 0.15]);

    expect(await main(["provider", "import", "--from-env", "--json"], runtime)).toBe(0);
    expect(client.requests.filter(({ spec }) => spec.method === "POST")).toHaveLength(firstCreates);
  });

  test("rejects a credential-shaped imported binding before listing", async () => {
    const runtime = createTestRuntime({
      env: {
        GATEWAY_PROVIDERS: JSON.stringify([
          { name: "openai", kind: "openai", base_url: "https://api.openai.com", api_key_var: "sk-live-key" },
        ]),
      },
    });

    expect(await main(["provider", "import", "--from-env"], runtime)).toBe(2);
    expect(runtime.client.requests).toHaveLength(0);
    expect(`${runtime.stdout()}${runtime.stderr()}`).not.toContain("sk-live-key");
  });
});

describe("offering id resolution", () => {
  test("a single offering id is resolved by an Admin API list", async () => {
    const runtime = createTestRuntime({
      script: {
        "GET /admin/v1/models": ok({
          object: "list",
          data: [{ id: "fast", offerings: [{ id: "o1" }] }],
        }),
        "GET /admin/v1/models/fast/offerings/o1": ok({
          object: "offering",
          offering: { id: "o1", model_id: "fast" },
        }),
      },
    });

    expect(await main(["model", "offering", "show", "o1", "--json"], runtime)).toBe(0);
    expect(runtime.client.requests.map(({ spec }) => `${spec.method} ${spec.path}`)).toEqual([
      "GET /admin/v1/models",
      "GET /admin/v1/models/fast/offerings/o1",
    ]);
  });
});
