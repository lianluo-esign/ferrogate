import { describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { PhysicalRoute, PlatformBillingGroupSource } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { fixedRequestIds } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const ROUTES: readonly PhysicalRoute[] = [
  {
    logicalModel: "shared-model",
    providerId: "provider-a",
    provider: "alpha",
    providerModel: "alpha-model",
    providerKind: "openai",
    baseUrl: "https://alpha.test/v1",
    apiKey: "sk-alpha",
    enabled: true,
    priority: 0,
  },
  {
    logicalModel: "shared-model",
    providerId: "provider-b",
    provider: "beta",
    providerModel: "beta-model",
    providerKind: "openai",
    baseUrl: "https://beta.test/v1",
    apiKey: "sk-beta",
    enabled: true,
    priority: 10,
  },
  {
    logicalModel: "alpha-only",
    providerId: "provider-a",
    provider: "alpha",
    providerModel: "alpha-only-model",
    providerKind: "openai",
    baseUrl: "https://alpha.test/v1",
    apiKey: "sk-alpha",
    enabled: true,
  },
];

const GROUPS: PlatformBillingGroupSource = {
  multiplierForGroup: async () => 1,
  routingForGroup: async (_env, groupId) =>
    groupId === "group-b" ? { providerIds: ["provider-b"] } : null,
};

function gateway() {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ROUTES),
        billingGroups: GROUPS,
        requestIds: fixedRequestIds,
      }),
    ],
  });
  const env = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify([
      {
        key: "fg_group_b",
        id: "key-group-b",
        tenant_id: "tenant-a",
        scopes: [],
        billing_group_id: "group-b",
      },
    ]),
  };
  return (path: string, init?: RequestInit) => app.request(`https://gw.test${path}`, init, env);
}

const headers = { authorization: "Bearer fg_group_b", "content-type": "application/json" };

describe("mounted billing-group routing", () => {
  it("lists only models reachable through the group's provider ids", async () => {
    const response = await gateway()("/v1/models", { headers });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: Array<{ id: string }> };

    expect(body.data.map((model) => model.id)).toEqual(["shared-model"]);
  });

  it("dispatches through the group's provider even when another provider is primary", async () => {
    const upstream = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-group",
        object: "chat.completion",
        choices: [
          { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
        ],
      }),
    );
    try {
      const response = await gateway()("/v1/chat/completions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          model: "shared-model",
          messages: [{ role: "user", content: "hi" }],
        }),
      });

      expect(response.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
      expect(upstream.lastRequest().url).toContain("beta.test");
      expect(upstream.lastRequest().body).toMatchObject({ model: "beta-model" });
    } finally {
      upstream.restore();
    }
  });

  it("does not fall back when the bound group cannot be resolved", async () => {
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: new InMemoryModelResolver(ROUTES),
          billingGroups: {
            multiplierForGroup: async () => 1,
            routingForGroup: async () => null,
          },
          requestIds: fixedRequestIds,
        }),
      ],
    });
    const response = await app.request(
      "https://gw.test/v1/models",
      { headers },
      {
        GATEWAY_NATIVE_API_KEYS: JSON.stringify([
          {
            key: "fg_group_b",
            id: "key-group-b",
            tenant_id: "tenant-a",
            scopes: [],
            billing_group_id: "group-b",
          },
        ]),
      },
    );

    expect(response.status).toBe(200);
    expect((await response.json()) as { data: unknown[] }).toMatchObject({ data: [] });
  });
});
