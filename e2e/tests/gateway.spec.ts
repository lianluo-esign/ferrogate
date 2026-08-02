/**
 * Black-box HTTP against a REAL `wrangler dev` running `apps/gateway`'s own
 * `wrangler.toml` and `src/index.ts`.
 *
 * Nothing here imports the app. That is the point: layer 1 (`apps/gateway/test`,
 * `SELF.fetch`) already proves the routing/auth table; this layer proves the
 * Worker actually *starts as a service* under `wrangler` and answers over a
 * socket, which `SELF` cannot observe.
 *
 * Every expectation below is on the app's REAL unconfigured-binding behavior.
 * The gateway's `[vars]` are fail-closed empties, so the model registry is
 * genuinely empty and no provider is ever called — no Cloudflare account, no
 * network, no LLM spend.
 *
 * The D1 bindings (`DB`, `BILLING_DB`/`CONTROL_DB`) DO exist and point at local
 * SQLite files that `playwright.config.ts` migrates before the servers start.
 * They are provisioned but EMPTY: no api-key row, no quota policy, no plan. That
 * is deliberate — the credential still comes from the injected
 * `GATEWAY_NATIVE_API_KEYS` var (the durable-NOT-FOUND fallback), and an empty
 * `quota_policies` means "no policy restricts", which is a very different state
 * from the "table is missing" that `d1QuotaPolicySource` correctly refuses with
 * `503 quota_resolution_unavailable`.
 */
import { expect, test } from "@playwright/test";

import { GATEWAY_API_KEY, GATEWAY_BASE_URL, type GatewayErrorEnvelope } from "../fixtures.js";

const bearer = { authorization: `Bearer ${GATEWAY_API_KEY}` };

test.describe("gateway liveness", () => {
  test("GET /healthz is served anonymously over real HTTP", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/healthz`);

    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toContain("application/json");
    // `runtime: "workers"` is the port marker: Rust reported `"pingora"`.
    // `version` was a recorded cutover gap — Rust's `HealthResponse.version` is
    // `env!("CARGO_PKG_VERSION")` and this document had no member for it — and
    // wave 17 closed it. Asserted here, over real HTTP against the deployed
    // `wrangler dev` Worker, so the member cannot quietly disappear again.
    expect(await res.json()).toEqual({
      status: "ok",
      service: "ferrogate-gateway",
      version: "0.0.0",
      runtime: "workers",
    });
  });

  test("GET /readyz reports ready", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/readyz`);

    expect(res.status()).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ready", service: "ferrogate-gateway" });
  });

  test("an inbound x-request-id is echoed on both correlation headers", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/healthz`, {
      headers: { "x-request-id": "e2e-correlation-probe" },
    });

    expect(res.status()).toBe(200);
    expect(res.headers()["x-request-id"]).toBe("e2e-correlation-probe");
    expect(res.headers()["x-trace-id"]).toBe("e2e-correlation-probe");
  });
});

test.describe("gateway authentication", () => {
  test("POST /v1/chat/completions with NO Authorization is 401", async ({ request }) => {
    const res = await request.post(`${GATEWAY_BASE_URL}/v1/chat/completions`, {
      headers: { "content-type": "application/json" },
      data: { model: "gpt-4o", messages: [{ role: "user", content: "hi" }] },
    });

    expect(res.status()).toBe(401);
    const body = (await res.json()) as GatewayErrorEnvelope;
    expect(body.error.code).toBe("missing_api_key");
    expect(body.error.type).toBe("ferrogate_error");
    // Rust `write_json_error` advertises the accepted scheme on every 401.
    expect(res.headers()["www-authenticate"]).toBe('Bearer error="missing_api_key"');
  });

  test("an unknown bearer is 401 invalid_api_key, not 403", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/v1/models`, {
      headers: { authorization: "Bearer fg_not_a_real_key" },
    });

    expect(res.status()).toBe(401);
    expect(((await res.json()) as GatewayErrorEnvelope).error.code).toBe("invalid_api_key");
  });

  test("GET /v1/models is guarded — the 200 below is not an open route", async ({ request }) => {
    // Negative control for the `listModels` shape test: without it, a gateway
    // that had lost its auth middleware entirely would still pass that test.
    const res = await request.get(`${GATEWAY_BASE_URL}/v1/models`);

    expect(res.status()).toBe(401);
    expect(((await res.json()) as GatewayErrorEnvelope).error.code).toBe("missing_api_key");
  });

  test("x-api-key is accepted as well as Authorization: Bearer", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/v1/models`, {
      headers: { "x-api-key": GATEWAY_API_KEY },
    });

    expect(res.status()).toBe(200);
  });
});

test.describe("gateway request validation", () => {
  test("authenticated + `messages` as a string is 400, not 401/500", async ({ request }) => {
    const res = await request.post(`${GATEWAY_BASE_URL}/v1/chat/completions`, {
      headers: { ...bearer, "content-type": "application/json" },
      data: { model: "gpt-4o", messages: "not-an-array" },
    });

    expect(res.status()).toBe(400);
    const body = (await res.json()) as GatewayErrorEnvelope;
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.type).toBe("ferrogate_error");
    // The Zod issue path must reach the caller — a bare "invalid request" would
    // be a regression in the error mapping even though the status is right.
    expect(body.error.message).toContain("messages");
    // The credential DID resolve; this is a body failure, not an auth failure.
    expect(res.headers()["www-authenticate"]).toBeUndefined();
  });

  test("an undocumented path is a 404 in the uniform envelope", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/v1/definitely-not-a-route`);

    expect(res.status()).toBe(404);
    const body = (await res.json()) as GatewayErrorEnvelope;
    expect(body.error.code).toBe("not_found");
    expect(body.error.type).toBe("ferrogate_error");
  });
});

test.describe("gateway model catalog", () => {
  test("GET /v1/models returns the OpenAI list shape", async ({ request }) => {
    const res = await request.get(`${GATEWAY_BASE_URL}/v1/models`, { headers: bearer });

    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toContain("application/json");

    const body = (await res.json()) as { object: string; data: unknown[] };
    expect(body.object).toBe("list");
    expect(Array.isArray(body.data)).toBe(true);

    // The catalog is EMPTY here, and that is the correct unconfigured-binding
    // answer rather than a gap in this test: `apps/gateway/src/index.ts` builds
    // `inferenceRouteModule()` with its offline in-memory defaults, which
    // resolve no models until `@ferrogate/routing` + a provider-secret binding
    // are wired. Asserting a populated catalog would require live Cloudflare
    // resources, which this layer deliberately does not have.
    // PORT-TODO(inventory-request-path.md §1.6 "Model resolution"): once the
    // routing snapshot is wired, extend this to assert a real model entry
    // (`id`, `object: "model"`, `owned_by`).
    expect(body.data).toEqual([]);
  });

  test("a resolvable-shaped request for an unknown model is a 400, not a 502", async ({
    request,
  }) => {
    // Proves the empty catalog above is enforced by the handler rather than
    // silently forwarded to some provider: with no model registered, a
    // well-formed body must be refused locally and NEVER cause egress.
    const res = await request.post(`${GATEWAY_BASE_URL}/v1/chat/completions`, {
      headers: { ...bearer, "content-type": "application/json" },
      data: { model: "gpt-4o", messages: [{ role: "user", content: "hi" }] },
    });

    expect(res.status()).toBe(400);
    expect(((await res.json()) as GatewayErrorEnvelope).error.code).toBe("model_not_found");
  });
});
