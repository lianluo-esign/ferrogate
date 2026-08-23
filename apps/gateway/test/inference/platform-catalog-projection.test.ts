import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { CallerScope } from "../../../control-plane/src/ports.js";
/**
 * The READ side of #889's platform-catalog WRITE half (#890), end to end in
 * workerd.
 *
 * #889 gave the platform default catalog CRUD storage in the CONTROL database
 * (`apps/control-plane/src/store/platform-model-catalog.ts`). This file proves
 * the other half of that join: rows written by that store, through the same
 * `PlatformModelCatalogStore` CRUD an operator uses, are read by the data plane
 * and become advertised, dispatchable models — with NO `GATEWAY_PROVIDERS` /
 * `GATEWAY_MODELS` in the env (both are pinned `"[]"` by `vitest.config.ts`, so
 * the platform tables are the ONLY model source here).
 *
 * The two apps are sibling workspaces; the join is by row content, exactly as
 * `guardrails/control-plane-projection.test.ts` joins the guardrail store.
 */
import { PlatformModelCatalogStore } from "../../../control-plane/src/store/platform-model-catalog.js";
import {
  emptyModelResolver,
  inferenceRouteModule,
  modelsFromEnv,
  platformModelCatalogFromControlData,
  tenantModelCatalogFromD1,
} from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { tenantDatabase } from "../../src/tenancy/index.js";
import { fixedRequestIds } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const db = bindings.CONTROL_DB as D1Database | undefined;
  if (db === undefined) {
    throw new Error(
      "platform catalog projection tests expect the `CONTROL_DB` binding (apps/gateway/wrangler.toml).",
    );
  }
  return db;
}

const OPERATOR: CallerScope = { kind: "platform_operator" };

const OPENAI_PROVIDER_ID = "pc_platform_openai";
const FALLBACK_PROVIDER_ID = "pc_platform_backup";
const MODEL_ID = "pm_platform_default";
const MODEL_NAME = "platform-default";

/**
 * Seed the platform catalog through the #889 store: one model, two providers,
 * two offerings (a primary and a fallback). Every write bumps the single
 * revision row in the same batch, which is the counter the loader gates its
 * cache on.
 */
async function seedPlatformCatalog(): Promise<void> {
  const store = new PlatformModelCatalogStore({ db: controlDb() });
  await store.createProvider(OPERATOR, {
    id: OPENAI_PROVIDER_ID,
    name: "platform-openai",
    kind: "openai",
    base_url: "https://api.openai.example/v1",
    cost_multiplier: 0.5,
    api_key_var: "PLATFORM_KEY",
    enabled: true,
  });
  await store.createProvider(OPERATOR, {
    id: FALLBACK_PROVIDER_ID,
    name: "platform-backup",
    kind: "openai-compatible",
    base_url: "https://api.backup.example/v1",
    upstream_protocol: "openai.responses",
    api_key_var: "PLATFORM_KEY",
    enabled: true,
  });
  await store.createModel(OPERATOR, {
    id: MODEL_ID,
    name: MODEL_NAME,
    owned_by: "platform",
    capabilities: ["chat", "streaming"],
    context_window: 128_000,
    enabled: true,
  });
  await store.upsertModelPrices(OPERATOR, [
    {
      id: "public:model:gpt-4o-mini-2024-07-18",
      model_key: "gpt-4o-mini-2024-07-18",
      name: "GPT-4o mini",
      source_type: "models_dev",
      source_provider_id: "openai",
      source_provider_name: "OpenAI",
      input_price_per_1m: 10,
      output_price_per_1m: 50,
      currency: "USD",
      enabled: true,
    },
  ]);
  await store.createOffering(OPERATOR, MODEL_ID, {
    id: "po_primary",
    provider_id: OPENAI_PROVIDER_ID,
    upstream_model_id: "gpt-4o-mini-2024-07-18",
    pricing_model_id: "public:model:gpt-4o-mini-2024-07-18",
    role: "primary",
    priority: 0,
    input_price_per_1m: 999,
    output_price_per_1m: 999,
  });
  await store.createOffering(OPERATOR, MODEL_ID, {
    id: "po_fallback",
    provider_id: FALLBACK_PROVIDER_ID,
    upstream_model_id: "backup-mini",
    role: "fallback",
    priority: 10,
    input_price_per_1m: 4,
    output_price_per_1m: 8,
  });
}

/** The deployed inference module, wired to the real platform + tenant sources. */
function gateway(overrides: Record<string, unknown> = {}) {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: modelsFromEnv,
        tenantCatalog: tenantModelCatalogFromD1(),
        platformCatalog: platformModelCatalogFromControlData(),
        requestIds: fixedRequestIds,
      }),
    ],
    // The deployed data plane mounts `tenantDatabase()` (GATEWAY_MIDDLEWARE);
    // `tenantModelsForRequest` reads the accessor it publishes.
    middleware: [tenantDatabase()],
  });
  // Spread the real workerd env so CONTROL_DB / TENANT_DATA / the api-key vars
  // are the ones the pool bound. Since #821 PR2-delete the `"off"` mode is
  // retired; under the `durable_object` default a platform operator resolves no
  // tenant (null tenant id) and a catalog-less fixture tenant reads its OWN
  // (empty) object catalog and falls back to the platform/env resolver — the
  // same "no tenant model wins here" posture `"off"` used to give.
  const fullEnv = {
    ...bindings,
    GATEWAY_TENANT_DB_ROUTING: "durable_object",
    PLATFORM_KEY: "sk-platform",
    ...overrides,
  };
  return (url: string, init?: RequestInit) => app.request(url, init, fullEnv as never);
}

function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}`, "content-type": "application/json" };
}

const BASE = "https://gw.test";
const MODELS = `${BASE}/v1/models`;
const CHAT = `${BASE}/v1/chat/completions`;

function okChatCompletion(): Response {
  return providerJson({
    id: "chatcmpl-1",
    object: "chat.completion",
    choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
  });
}

async function listedModelIds(res: Response): Promise<string[]> {
  const body = (await res.json()) as { data: { id: string }[] };
  return body.data.map((model) => model.id);
}

describe("platform model catalog projected into the data plane (#890)", () => {
  beforeAll(async () => {
    await seedPlatformCatalog();
  });

  it("advertises the platform model to a platform operator with no env models", async () => {
    const call = gateway();
    const res = await call(MODELS, { headers: bearer("fg_root") });
    expect(res.status).toBe(200);
    expect(await listedModelIds(res)).toContain(MODEL_NAME);
  });

  it("advertises the platform model to a catalog-less tenant", async () => {
    const call = gateway();
    const res = await call(MODELS, { headers: bearer("fg_tenant_unscoped") });
    expect(res.status).toBe(200);
    expect(await listedModelIds(res)).toContain(MODEL_NAME);
  });

  it("keeps the public price for billing and carries supplier cost separately", async () => {
    const source = platformModelCatalogFromControlData({ ttlMs: 0 });
    const loaded = await source.load({
      env: { ...bindings, PLATFORM_KEY: "sk-platform" } as never,
      fallback: emptyModelResolver,
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    const model = loaded.inputs.models.find((candidate) => candidate.name === MODEL_NAME);
    expect(model?.input_price_per_1m).toBe(10);
    expect(model?.output_price_per_1m).toBe(50);
    const candidates = loaded.models?.candidates?.(MODEL_NAME) ?? [];
    const primary = candidates.find((candidate) => candidate.provider === "platform-openai");
    expect(primary?.inputPricePer1m).toBe(10);
    expect(primary?.outputPricePer1m).toBe(50);
    expect(primary?.providerCostMultiplier).toBe(0.5);
    const fallback = candidates.find((candidate) => candidate.provider === "platform-backup");
    expect(fallback?.upstreamProtocol).toBe("openai.responses");
  });

  it("dispatches the platform model's primary leg", async () => {
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway();
      const res = await call(CHAT, {
        method: "POST",
        headers: bearer("fg_root"),
        body: JSON.stringify({ model: MODEL_NAME, messages: [{ role: "user", content: "hello" }] }),
      });
      expect(res.status).toBe(200);
      const dispatched = provider.lastRequest();
      // The PRIMARY leg: the openai provider's base url and upstream model id,
      // not the fallback's (`api.backup.example` / `backup-mini`).
      expect(dispatched.url).toContain("api.openai.example");
      expect((dispatched.body as { model?: string }).model).toBe("gpt-4o-mini-2024-07-18");
    } finally {
      provider.restore();
    }
  });

  it("picks up a later CRUD edit within one TTL on a warm isolate", async () => {
    // Reuse ONE env object so the loader cache is warm from the first call; the
    // store's same-batch revision bump is what invalidates it — an isolate
    // restart is not required.
    const call = gateway();
    const before = await listedModelIds(await call(MODELS, { headers: bearer("fg_root") }));
    expect(before).not.toContain("platform-late");

    const store = new PlatformModelCatalogStore({ db: controlDb() });
    await store.createModel(OPERATOR, {
      id: "pm_late",
      name: "platform-late",
      capabilities: ["chat"],
      enabled: true,
    });
    await store.createOffering(OPERATOR, "pm_late", {
      id: "po_late",
      provider_id: OPENAI_PROVIDER_ID,
      upstream_model_id: "gpt-4o-late",
      role: "primary",
    });

    const after = await listedModelIds(await call(MODELS, { headers: bearer("fg_root") }));
    expect(after).toContain("platform-late");
  });

  it("lets the env registry win when no platform catalog is bound (bootstrap)", async () => {
    // No control object bound (`CONTROL_DATA` unset) and a real env model:
    // `controlDatabaseFrom` returns undefined ⇒ bootstrap ⇒ the env registry is
    // authoritative.
    const call = gateway({
      CONTROL_DATA: undefined,
      GATEWAY_PROVIDERS: JSON.stringify([
        {
          name: "env-provider",
          kind: "openai",
          base_url: "https://env.test/v1",
          api_key_var: "ENV_KEY",
        },
      ]),
      GATEWAY_MODELS: JSON.stringify([
        { name: "env-only-model", provider: "env-provider", provider_model: "env-upstream" },
      ]),
      ENV_KEY: "sk-env",
    });
    const ids = await listedModelIds(await call(MODELS, { headers: bearer("fg_root") }));
    expect(ids).toContain("env-only-model");
    expect(ids).not.toContain(MODEL_NAME);
  });
});
