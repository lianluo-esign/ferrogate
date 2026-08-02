/**
 * The inference `RouteModule` seam — the adapter that mounts the eight inference
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
import { describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { INFERENCE_OPERATION_IDS, createGatewayApp } from "../../src/routes/index.js";
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

describe("inferenceRouteModule", () => {
  it("claims exactly the 8 contract inference operation ids", () => {
    expect(new Set(inferenceRouteModule().operationIds)).toEqual(new Set(INFERENCE_OPERATION_IDS));
    // 6 -> 7 with `countMessageTokens` (issue #671) and 7 -> 8 with `getModel`
    // (GET /v1/models/{model}, issue #670). Both sides wrote 7 independently,
    // so the merge kept 7 silently; 8 is the re-derived truth.
    expect(inferenceRouteModule().operationIds).toHaveLength(8);
  });

  it("registers all 8 on the contract-driven router", () => {
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
