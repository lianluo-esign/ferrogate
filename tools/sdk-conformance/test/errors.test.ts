/**
 * The ERROR TAXONOMY — "a client that cannot parse our 401/403/429/503 bodies
 * is not compatible", and this is where gateway compatibility usually breaks.
 *
 * Every case below asserts on the exception the SDK CONSTRUCTED, never on a raw
 * status code. That distinction is the whole file: the SDKs classify by status
 * into typed subclasses (`AuthenticationError`, `PermissionDeniedError`,
 * `RateLimitError`, `InternalServerError`) and then read `code` / `type` /
 * `message` / `requestID` out of the BODY. Application code catches the class
 * and switches on `err.code`, so a body FerroGate shapes differently is a real
 * behavioural difference even when the status is right.
 *
 * Where FerroGate's answer differs from what an OpenAI-native client would see
 * from `api.openai.com`, the divergence is asserted AS IT IS and marked
 * `DIVERGENCE` with the file that produces it. This suite reports; it does not
 * quietly adjust an expectation until it goes green, and it does not fix the
 * gateway — see the PR for #675 for the write-up and follow-up issues.
 */
import { env } from "cloudflare:test";
import { APIError, AuthenticationError, PermissionDeniedError, RateLimitError } from "openai";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { interceptUpstream, openaiClient, upstreamJson } from "./harness.js";

const COMPLETION = {
  id: "chatcmpl-errors",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
};

/** A minimal, always-valid chat request. */
const REQUEST = {
  model: "gpt-4o-mini",
  messages: [{ role: "user" as const, content: "hi" }],
};

/**
 * The gateway prefers the CONTROL database over the `GATEWAY_QUOTA_POLICIES`
 * var whenever one is bound, and `apps/gateway/wrangler.toml` binds it — so the
 * 429 leg has to seed a real row rather than rely on the var. This is the same
 * durable path a production deployment enforces on.
 */
beforeAll(async () => {
  const control = (env as unknown as { CONTROL_DB?: D1Database; BILLING_DB?: D1Database })
    .CONTROL_DB;
  if (control === undefined) return;
  await control
    .prepare(
      "INSERT OR REPLACE INTO quota_policies (id, scope_type, scope_id, rpm_limit, enabled) " +
        "VALUES (?, 'tenant', 'tenant_sdk_rpm', 2, 1)",
    )
    .bind("quota_conformance_rpm")
    .run();
});

const mutableEnv = env as unknown as Record<string, unknown>;

afterEach(() => {
  delete mutableEnv["GATEWAY_DRAIN"];
});

/** Run `body` and return the error it threw (failing if it did not throw). */
async function captured(body: () => Promise<unknown>): Promise<APIError> {
  try {
    await body();
  } catch (error) {
    if (error instanceof APIError) return error;
    throw error;
  }
  throw new Error("expected the SDK to throw an APIError");
}

describe("openai SDK — error taxonomy", () => {
  it("401 — an unknown credential becomes AuthenticationError", async () => {
    const error = await captured(() =>
      openaiClient({ apiKey: "fg_not_a_key" }).chat.completions.create(REQUEST),
    );

    expect(error).toBeInstanceOf(AuthenticationError);
    expect(error.status).toBe(401);
    // Read off the body by the SDK, which is what application code switches on.
    expect(error.code).toBe("invalid_api_key");
    expect(error.message).toContain("invalid API key");
    // DIVERGENCE (apps/gateway/src/inference/errors.ts): OpenAI's own bodies
    // carry `type: "invalid_request_error"`; every FerroGate error carries the
    // single constant `ferrogate_error`. The SDK does not care — it classifies
    // by STATUS — but code that switches on `err.type` will not match.
    expect(error.type).toBe("ferrogate_error");
    // The correlation id the SDK exposes as `error.requestID`, taken from the
    // `x-request-id` response header, and the SAME id the body carries.
    expect(error.requestID).toEqual((error.error as { request_id: string }).request_id);
    expect(error.requestID).not.toBeNull();
  });

  it("401 — a REVOKED key is indistinguishable from an unknown one", async () => {
    const error = await captured(() =>
      openaiClient({ apiKey: "fg_conformance_suspended" }).chat.completions.create(REQUEST),
    );

    expect(error).toBeInstanceOf(AuthenticationError);
    expect(error.code).toBe("invalid_api_key");
  });

  it("403 — a suspended TENANT becomes PermissionDeniedError, not a 401", async () => {
    const error = await captured(() =>
      openaiClient({ apiKey: "fg_conformance_tenant_down" }).chat.completions.create(REQUEST),
    );

    expect(error).toBeInstanceOf(PermissionDeniedError);
    expect(error.status).toBe(403);
    expect(error.code).toBe("tenancy_suspended");
  });

  it("400 — an unknown model is a BadRequestError carrying `model_not_found`", async () => {
    const error = await captured(() =>
      openaiClient().chat.completions.create({ ...REQUEST, model: "no-such-model" }),
    );

    // DIVERGENCE (apps/gateway/src/inference/handlers.ts:396,406): the OpenAI
    // API answers 404 for an unknown model, FerroGate answers 400. The SDK
    // therefore raises `BadRequestError` where a client would have caught
    // `NotFoundError`. Reported, deliberately NOT fixed here — the status is a
    // behavioural choice inherited from the Rust gateway and changing it is a
    // contract change, not a test change.
    expect(error.status).toBe(400);
    expect(error.code).toBe("model_not_found");
    expect(error.message).toContain("no-such-model");
  });

  it("relays a PROVIDER error verbatim — status, code, type and message", async () => {
    // The upstream's own error taxonomy must survive the hop, or a caller
    // debugging a bad parameter is told the gateway is broken instead.
    const upstream = interceptUpstream(() =>
      upstreamJson(
        {
          error: {
            message: "Unrecognized request argument: foo",
            type: "invalid_request_error",
            param: "foo",
            code: null,
          },
        },
        400,
      ),
    );
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      expect(error.status).toBe(400);
      expect(error.message).toContain("Unrecognized request argument");
      // NOT re-wrapped in the FerroGate envelope: the provider's own `type` and
      // `param` reach the SDK, so `err.param`-based handling keeps working.
      expect(error.type).toBe("invalid_request_error");
      expect(error.param).toBe("foo");
    } finally {
      upstream.restore();
    }
  });

  it("DIVERGENCE: a provider 429's `retry-after` never reaches the client", async () => {
    const upstream = interceptUpstream(
      () =>
        new Response(JSON.stringify({ error: { message: "slow down", type: "rate_limit_error" } }), {
          status: 429,
          headers: {
            "content-type": "application/json",
            // Everything a client would pace itself with:
            "retry-after": "7",
            "x-ratelimit-remaining-requests": "0",
            "x-ratelimit-reset-requests": "7s",
          },
        }),
    );
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      // The STATUS and BODY survive — the SDK still raises `RateLimitError`.
      expect(error).toBeInstanceOf(RateLimitError);
      expect(error.message).toContain("slow down");

      // DIVERGENCE, reported not fixed: the gateway answers with its OWN header
      // set (`gatewayHeaders`, apps/gateway/src/inference/errors.ts) and drops
      // every upstream header. Both SDKs read `retry-after` / `retry-after-ms`
      // to time their backoff, and OpenAI documents the `x-ratelimit-*` family
      // as the way clients pace themselves. Behind FerroGate a client sees
      // NEITHER, so it falls back to a blind exponential schedule and cannot
      // pace at all.
      expect(error.headers?.get("retry-after")).toBeNull();
      expect(error.headers?.get("x-ratelimit-remaining-requests")).toBeNull();
    } finally {
      upstream.restore();
    }
  });

  it("DIVERGENCE: an empty `messages` array is forwarded rather than refused", async () => {
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      await openaiClient().chat.completions.create({ model: "gpt-4o-mini", messages: [] });

      // The OpenAI API answers 400 `invalid_request_error` for an empty
      // `messages` array. FerroGate's request schema accepts it and dispatches,
      // so the refusal — if any — comes from the provider, one hop later and
      // billed as an upstream call. Asserted as it IS; reported in the PR.
      expect(upstream.requests).toHaveLength(1);
      expect((upstream.last().body as { messages: unknown[] }).messages).toEqual([]);
    } finally {
      upstream.restore();
    }
  });

  it("429 — an exhausted RPM window becomes RateLimitError", async () => {
    const client = openaiClient({ apiKey: "fg_conformance_throttled" });
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      // The tenant's window is 2/min (seeded above). Spend it, then trip it.
      await client.chat.completions.create(REQUEST);
      await client.chat.completions.create(REQUEST);
      const error = await captured(() => client.chat.completions.create(REQUEST));

      expect(error).toBeInstanceOf(RateLimitError);
      expect(error.status).toBe(429);
      expect(error.code).toBe("rate_limit_exceeded");
      // DIVERGENCE, and the one with real client consequences: FerroGate emits
      // NO `Retry-After`. `apps/gateway/src/ratelimit/ports.ts:269` documents
      // this as deliberate parity with the Rust gateway (which emitted none
      // either), but both SDKs read `retry-after` / `retry-after-ms` to time
      // their backoff and fall back to a blind exponential schedule without it.
      // So a throttled client retries on ITS schedule, not the gateway's.
      expect(error.headers?.get("retry-after")).toBeNull();
    } finally {
      upstream.restore();
    }
  });

  it("503 — an operator drain becomes InternalServerError with a 503 status", async () => {
    mutableEnv["GATEWAY_DRAIN"] = "true";
    const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

    expect(error.status).toBe(503);
    expect(error.code).toBe("node_draining");
    // The SDK collapses every 5xx into `InternalServerError`; the DISTINCTION a
    // caller needs ("retry me later" vs "I am broken") lives only in `status`
    // and `code`, which is why both are asserted.
    expect(error.constructor.name).toBe("InternalServerError");
    expect(error.message).toContain("draining");
  });

  it("keeps the envelope shape identical across every status", async () => {
    // One assertion, four statuses: whatever else changes, the four members the
    // SDKs read are always present and always in the same place.
    const cases: Array<{ client: ReturnType<typeof openaiClient>; body: typeof REQUEST }> = [
      { client: openaiClient({ apiKey: "fg_not_a_key" }), body: REQUEST },
      { client: openaiClient({ apiKey: "fg_conformance_tenant_down" }), body: REQUEST },
      { client: openaiClient(), body: { ...REQUEST, model: "no-such-model" } },
    ];

    for (const { client, body } of cases) {
      const error = await captured(() => client.chat.completions.create(body));
      expect(error.error).toMatchObject({
        message: expect.any(String),
        type: "ferrogate_error",
        code: expect.any(String),
        request_id: expect.any(String),
      });
    }
  });

  it("DIVERGENCE: `models.retrieve()` is not routed at all", async () => {
    // `GET /v1/models/{model}` is part of the OpenAI surface every SDK exposes
    // as `client.models.retrieve(id)`. The gateway routes the LIST but not the
    // item, so the call 404s with the router's generic `not_found` — i.e. the
    // one SDK method whose failure looks like a wrong base URL rather than an
    // unimplemented operation. Reported, not fixed.
    const error = await captured(() => openaiClient().models.retrieve("gpt-4o-mini"));

    expect(error.status).toBe(404);
    expect(error.code).toBe("not_found");
    expect(error.message).toContain("no route for GET /v1/models/gpt-4o-mini");
  });
});
