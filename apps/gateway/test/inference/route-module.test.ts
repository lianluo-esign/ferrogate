/**
 * The inference `RouteModule` seam — the adapter that mounts the twelve inference
 * operations on the contract-driven gateway router.
 *
 * `test/inference/*.test.ts` drives the standalone `createInferenceRouter`
 * directly. This file drives the SAME handlers through the composition the
 * Worker actually deploys — `createGatewayApp({ modules: [inferenceRouteModule(
 * deps)] })` — because that is where the adapter could quietly lose behavior:
 * the bounded body reader, the Zod 400, SSE relaying, or the single-guard auth
 * invariant. Only the ports differ from production (a fake model catalog and an
 * intercepted outbound `fetch`); the router, the guard, and the error envelope
 * are the real ones.
 */
import type { MiddlewareHandler } from "hono";
import { describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { TenantModelCatalogSource } from "../../src/inference/index.js";
import type { GatewayEnv } from "../../src/ports.js";
import { INFERENCE_OPERATION_IDS, createGatewayApp } from "../../src/routes/index.js";
import {
  TENANT_DATABASE_VAR,
  type TenancyContext,
  type TenantDatabaseAccessor,
} from "../../src/tenancy/index.js";
import { ALL_ROUTES, errorBody, fixedRequestIds } from "./fixtures.js";
import {
  OPENAI_CHAT_STREAM_FRAMES,
  interceptProviderFetch,
  providerSse,
  readBody,
  sseBytes,
} from "./provider-mock.js";

const BASE = "https://gw.test";

/** One operator-authored static key ⇒ the wildcard scope, so the guard passes. */
const ENV = {
  GATEWAY_STATIC_API_KEYS: JSON.stringify([
    { key: "fg_root", id: "key_root", platform_operator: true },
  ]),
};

const AUTHED = { authorization: "Bearer fg_root", "content-type": "application/json" };

function gateway(limits?: { inferenceBodyMaxBytes?: number }) {
  const { app, router } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ALL_ROUTES),
        requestIds: fixedRequestIds,
        ...(limits === undefined ? {} : { limits }),
      }),
    ],
  });
  return {
    router,
    call: (path: string, init?: RequestInit) => app.request(`${BASE}${path}`, init, ENV),
  };
}

function tenantCatalogGateway() {
  const route = {
    logicalModel: "tenant-model",
    provider: "tenant-provider",
    providerModel: "tenant-upstream",
    providerKind: "openai",
    baseUrl: "https://tenant.test/v1",
    enabled: true,
  } as const;
  const database = {} as D1Database;
  const accessor: TenantDatabaseAccessor = {
    tenantId: "tenant_a",
    mode: "shared_development",
    handle: async () => ({
      tenantId: "tenant_a",
      db: database,
      source: "shared_development",
      supportsAtomicBatch: true,
    }),
    db: async () => database,
    control: () => database,
  };
  const mount: MiddlewareHandler<GatewayEnv> = async (c, next) => {
    (c as unknown as TenancyContext).set(TENANT_DATABASE_VAR, accessor);
    await next();
  };
  const source: TenantModelCatalogSource = {
    async load(input) {
      expect(input.tenantId).toBe("tenant_a");
      expect(input.db).toBe(database);
      return { ok: true, models: new InMemoryModelResolver([route]) };
    },
  };
  const { app } = createGatewayApp({
    modules: [inferenceRouteModule({ tenantCatalog: source })],
    middleware: [mount],
  });
  return (path: string, init?: RequestInit) =>
    app.request(`https://gw.test${path}`, init, {
      GATEWAY_STATIC_API_KEYS: JSON.stringify([
        { key: "fg_tenant", id: "key_tenant", tenant_id: "tenant_a", scopes: [] },
      ]),
      GATEWAY_TENANT_DB_ROUTING: "shared_development",
    });
}

describe("inferenceRouteModule", () => {
  it("loads the tenant resolver before delegating into the inner app", async () => {
    const call = tenantCatalogGateway();
    const response = await call("/v1/models", {
      headers: { authorization: "Bearer fg_tenant" },
    });

    expect(response.status).toBe(200);
    const listing = (await response.json()) as { data: { id: string }[] };
    expect(listing.data.map((model) => model.id)).toContain("tenant-model");
  });

  it("claims exactly the 14 contract inference operation ids", () => {
    expect(new Set(inferenceRouteModule().operationIds)).toEqual(new Set(INFERENCE_OPERATION_IDS));
    // 6 -> 7 with `countMessageTokens` (issue #671), 7 -> 8 with `getModel`
    // (GET /v1/models/{model}, issue #670), 8 -> 9 with `createRerank`
    // (POST /v1/rerank, issue #676) and 9 -> 12 with the audio surface
    // (`createTranscription`, `createTranslation`, `createSpeech`, issue #703).
    // #671 and #670 both wrote 7 independently, so that merge kept 7 silently;
    // this number is COUNTED off the list rather than incremented from a
    // parent's. #689's `getResponse` / `deleteResponse` take it to 14, counted
    // off the list the module actually claims.
    expect(inferenceRouteModule().operationIds).toHaveLength(14);
  });

  it("registers all 14 on the contract-driven router", () => {
    const { router } = gateway();
    for (const operationId of INFERENCE_OPERATION_IDS) {
      expect(router.registeredOperationIds(), operationId).toContain(operationId);
    }
  });

  it("serves GET /v1/models through the mounted module", async () => {
    const { call } = gateway();
    const res = await call("/v1/models", { headers: AUTHED });
    expect(res.status).toBe(200);
    const listing = (await res.json()) as { object: string; data: { id: string }[] };
    expect(listing.object).toBe("list");
    // The disabled route is filtered out by the handler, so this is the
    // handler's own answer and not a router stub.
    expect(listing.data.map((model) => model.id)).not.toContain("retired-model");
    expect(listing.data.map((model) => model.id)).toContain("gpt-4o-mini");
  });

  it("preserves SSE streaming byte-for-byte through the delegation", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const { call } = gateway();
      const res = await call("/v1/chat/completions", {
        method: "POST",
        headers: AUTHED,
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: "hi" }],
          stream: true,
        }),
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/event-stream");
      expect(res.headers.get("cache-control")).toBe("no-cache");
      // The adapter must hand back the provider's stream, not a buffered copy
      // of it re-encoded by the outer app.
      expect(await readBody(res)).toBe(sseBytes(OPENAI_CHAT_STREAM_FRAMES));
    } finally {
      provider.restore();
    }
  });

  it("preserves the inner Zod 400 (invalid_request)", async () => {
    const { call } = gateway();
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: "{}",
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("preserves invalid_json as distinct from invalid_request", async () => {
    const { call } = gateway();
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: "{not json",
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_json");
  });

  it("preserves the bounded body read (payload_too_large)", async () => {
    const { call } = gateway({ inferenceBodyMaxBytes: 32 });
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "x".repeat(4096) }],
      }),
    });
    expect(res.status).toBe(413);
    expect((await errorBody(res)).error.code).toBe("payload_too_large");
  });

  it("leaves authentication to the single contract guard — and applies it once", async () => {
    const { call } = gateway();
    // No credential: the OUTER guard refuses before the inner router is reached,
    // so the answer is the gateway's envelope, not the inference module's.
    const anonymous = await call("/v1/models");
    expect(anonymous.status).toBe(401);
    expect((await errorBody(anonymous)).error.code).toBe("missing_api_key");

    // A valid credential is accepted exactly once — a second guard on the inner
    // app (which has none) would turn this into a 401 as well.
    const authed = await call("/v1/models", { headers: AUTHED });
    expect(authed.status).toBe(200);
  });

  it("refuses to be registered twice on the same router", () => {
    const { router } = gateway();
    expect(() => inferenceRouteModule().register(router)).toThrow(/already registered/);
  });
});
