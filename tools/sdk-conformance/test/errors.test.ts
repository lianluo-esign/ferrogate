/**
 * The ERROR TAXONOMY — "a client that cannot parse our 4xx/5xx bodies is not
 * compatible", and this is where gateway compatibility usually breaks.
 *
 * Every status the gateway can put on the wire for an SDK call is exercised
 * here: 400, 401, 403, 404, 429, 500, 502 and 503. The 5xx half is the half
 * that decides whether a client can tell "retry me" from "I am broken", so the
 * three ways a 5xx is produced are kept apart deliberately —
 *
 *  - ORIGINATED by the gateway (`errorResponse`, `apps/gateway/src/inference/
 *    errors.ts`): a provider transport failure ⇒ 502 `provider_dispatch_error`,
 *    an operator drain ⇒ 503 `node_draining`, an upstream error body nobody can
 *    parse ⇒ the upstream's status with `provider_invalid_error_body` (#733);
 *  - RELAYED from the provider verbatim (`rawUpstreamResponse`, same file): the
 *    provider's own status, `content-type` and error object reach the caller,
 *    so a provider 500 arrives with the PROVIDER's taxonomy, not FerroGate's.
 *    Conditional since #733 — the relay applies to a body that decodes to a
 *    JSON object, which is the only kind a client can read;
 *  - UNHANDLED, which is now ALSO the envelope (#733). It used not to be: an
 *    inner `Hono` app with no `onError` answered Hono's default `text/plain`
 *    500, so the one status a caller most needs to classify was the one status
 *    with no `code`, `type` or `request_id`.
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
import {
  APIError,
  AuthenticationError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
} from "openai";
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
    // DELIBERATE: OpenAI's own bodies carry `type: "invalid_request_error"`;
    // FerroGate supplies its single constant `ferrogate_error` instead, so
    // `err.type`-based handling never matches. The SDKs classify by STATUS,
    // so `err.type`-based code is rare — this is the same design choice the
    // Anthropic-side test documents.
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

    // DELIBERATE (apps/gateway/src/inference/handlers.ts:planUpstream): the
    // OpenAI API answers 404 for an unknown model, FerroGate answers 400. The
    // SDK therefore raises `BadRequestError` where a client would have caught
    // `NotFoundError`. This is a behavioural choice inherited from the Rust
    // gateway: on POST the ROUTE exists and the caller's BODY names something
    // unusable, which is a bad request — the discovery path (GET /v1/models/
    // {model}) answers 404 as the OpenAI API does.
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

  it("a provider 429's `retry-after` reaches the client (#726, was a DIVERGENCE)", async () => {
    const upstream = interceptUpstream(
      () =>
        new Response(
          JSON.stringify({ error: { message: "slow down", type: "rate_limit_error" } }),
          {
            status: 429,
            headers: {
              "content-type": "application/json",
              // Everything a client would pace itself with:
              "retry-after": "7",
              "x-ratelimit-remaining-requests": "0",
              "x-ratelimit-reset-requests": "7s",
            },
          },
        ),
    );
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      // The STATUS and BODY survive — the SDK still raises `RateLimitError`.
      expect(error).toBeInstanceOf(RateLimitError);
      expect(error.message).toContain("slow down");

      // FIXED by #726. This block previously asserted BOTH of these were
      // `null`, and said so as a reported-not-fixed divergence: the gateway
      // answered with its own `gatewayHeaders` set and dropped every upstream
      // header, so an SDK behind FerroGate fell back to a blind exponential
      // schedule. `relayedRateLimitHeaders`
      // (apps/gateway/src/inference/errors.ts) now relays the two documented
      // pacing families, and the assertions are inverted deliberately.
      //
      // Read off the exception the SDK CONSTRUCTED, which is what its own
      // `calculateDefaultRetryTimeoutMillis` reads when retries are enabled.
      expect(error.headers?.get("retry-after")).toBe("7");
      expect(error.headers?.get("x-ratelimit-remaining-requests")).toBe("0");
      expect(error.headers?.get("x-ratelimit-reset-requests")).toBe("7s");
    } finally {
      upstream.restore();
    }
  });

  it("an empty `messages` array is refused with 400 before dispatch", async () => {
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      const error = await captured(() =>
        openaiClient().chat.completions.create({ model: "gpt-4o-mini", messages: [] }),
      );

      // FIXED by #727: the request schema now rejects an empty `messages` array
      // with 400 `invalid_request`, so no upstream call is made.
      expect(error.status).toBe(400);
      expect(error.code).toBe("invalid_request");
      expect(error.message).toContain("non-empty");
      expect(upstream.requests).toHaveLength(0);
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
      // FIXED by #726. This used to assert `retry-after` was `null` and called
      // it "the divergence with real client consequences": FerroGate's own 429
      // told a throttled client nothing, so it retried on ITS schedule rather
      // than the gateway's. The values are derived from the window that refused
      // (`apps/gateway/src/ratelimit/headers.ts`), never constants.
      const retryAfter = Number(error.headers?.get("retry-after"));
      expect(Number.isInteger(retryAfter)).toBe(true);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);
      // The tenant's seeded cap is 2/min (see the `beforeAll` above) — the
      // number an SDK needs to size its own concurrency, and one no constant
      // implementation would produce.
      expect(error.headers?.get("x-ratelimit-limit-requests")).toBe("2");
      expect(error.headers?.get("x-ratelimit-remaining-requests")).toBe("0");
      expect(error.headers?.get("x-ratelimit-reset-requests")).toBe(`${retryAfter}s`);
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

  it("502 — a provider TRANSPORT failure is the gateway's OWN envelope", async () => {
    // The single most common 5xx behind a gateway: the upstream never answers.
    // `dispatchUpstream` (apps/gateway/src/inference/handlers.ts:674) catches
    // the `fetch` rejection and originates a 502 — nothing is relayed, so this
    // is FerroGate's envelope on a 5xx, which nothing else in the suite covers.
    const upstream = interceptUpstream(() => {
      throw new TypeError("Network connection lost.");
    });
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      expect(error.status).toBe(502);
      // The `openai` SDK has no 502 subclass: every status >= 500 becomes
      // `InternalServerError`. So `err.status` is the ONLY thing that separates
      // "the provider is unreachable" (502) from "the gateway is draining"
      // (503) for a caller, and both are asserted for that reason.
      expect(error.constructor.name).toBe("InternalServerError");
      // Typed, not a parse failure: the body decoded into the four members.
      expect(error.code).toBe("provider_dispatch_error");
      expect(error.type).toBe("ferrogate_error");
      expect(error.message).toContain("provider dispatch failed");
      expect(error.requestID).not.toBeNull();
      expect(error.requestID).toEqual((error.error as { request_id: string }).request_id);
    } finally {
      upstream.restore();
    }
  });

  it("502 — a STREAMING call fails before the first frame, not with an empty stream", async () => {
    // A stream is the case where "typed error, not a parse failure" is easiest
    // to get wrong: the SDK has already been asked for an async iterator, and a
    // gateway that answered 502 with `content-type: text/event-stream` (or that
    // opened the stream and closed it) would hand the caller an iterator that
    // yields nothing and completes — a silent empty answer. It does not: the
    // 502 arrives as JSON before the iterator exists and `create()` rejects.
    const upstream = interceptUpstream(() => {
      throw new TypeError("Network connection lost.");
    });
    try {
      const error = await captured(async () => {
        const stream = await openaiClient().chat.completions.create({ ...REQUEST, stream: true });
        for await (const chunk of stream) void chunk;
      });

      expect(error.status).toBe(502);
      expect(error.code).toBe("provider_dispatch_error");
      // The STREAMING dispatch site has its own message (`provider streaming
      // request failed`), so this is genuinely the other code path.
      expect(error.message).toContain("streaming");
    } finally {
      upstream.restore();
    }
  });

  it("500 — a provider 500 is relayed with the PROVIDER's taxonomy intact", async () => {
    // `rawUpstreamResponse` echoes the provider's status and body, so an
    // `api.openai.com` 500 reaches the caller exactly as it would without the
    // gateway in the path. This is the ONLY 500 an SDK caller sees on a
    // well-behaved request — see the `internal_error` case below for why.
    const upstream = interceptUpstream(() =>
      upstreamJson(
        {
          error: {
            message: "The server had an error while processing your request",
            type: "server_error",
            param: null,
            code: null,
          },
        },
        500,
      ),
    );
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      expect(error.status).toBe(500);
      expect(error.constructor.name).toBe("InternalServerError");
      // NOT re-wrapped: `server_error` is OpenAI's own `type`, and a caller
      // that switches on it keeps working through FerroGate.
      expect(error.type).toBe("server_error");
      expect(error.message).toContain("The server had an error");
      // The provider sent `code: null`, and that is what the SDK reports —
      // the gateway does not invent a code of its own.
      expect(error.code).toBeNull();
    } finally {
      upstream.restore();
    }
  });

  it("502 — a NON-JSON provider error body is WRAPPED in the FerroGate envelope", async () => {
    // The case that decides "a client that cannot parse our 502 body is not
    // compatible": a 502 from a CDN or a load balancer in front of the provider
    // is an HTML page.
    //
    // FLIPPED BY #733. This case used to assert the divergence it found —
    // verbatim relay, so `error.error` / `error.code` / `error.type` were all
    // `undefined` and `error.message` was a chunk of markup. The report's own
    // argument ("FerroGate ALREADY wraps a provider TRANSPORT failure in its
    // own envelope; an unparseable provider ERROR body is the same class of
    // event from the caller's side") is what closed it, so the four members are
    // now present here exactly as they are on the transport-failure case above.
    const upstream = interceptUpstream(
      () =>
        new Response(
          "<html><head><title>502 Bad Gateway</title></head><body>bad gateway</body></html>",
          { status: 502, headers: { "content-type": "text/html; charset=utf-8" } },
        ),
    );
    try {
      const error = await captured(() => openaiClient().chat.completions.create(REQUEST));

      // The UPSTREAM's status is preserved, not collapsed to a fixed 502: a 429
      // is paced, a 503 is retried and a 500 is not, and flattening them would
      // delete the only distinction the caller had left.
      expect(error.status).toBe(502);
      expect(error.constructor.name).toBe("InternalServerError");
      // Typed, not a parse failure — the members application code switches on.
      expect(error.code).toBe("provider_invalid_error_body");
      expect(error.type).toBe("ferrogate_error");
      expect((error.error as { request_id: string }).request_id).toEqual(expect.any(String));
      // MEANINGFUL rather than `internal_error`: it names the event and carries
      // the upstream status and media type, which is what a caller can act on.
      expect(error.message).toContain("502");
      expect(error.message).toContain("text/html");
      // And the upstream's bytes do NOT reach the client. An error page from a
      // load balancer is where a backend leaks its own internals, and none of
      // it is FerroGate's to forward.
      expect(error.message).not.toContain("<html>");
      expect(error.headers?.get("x-request-id")).toEqual(expect.any(String));
    } finally {
      upstream.restore();
    }
  });

  it("500 — an UNHANDLED failure answers the envelope like everything else", async () => {
    // FerroGate's contract declares `internal_error` (500) — `STATUS_BY_CODE`,
    // apps/gateway/src/middleware/errors.ts:110. No CLASSIFIED refusal on the
    // SDK surface produces it (every one carries its own status, and the three
    // `HttpError(500, "internal_error")` sites in `middleware/auth.ts` and
    // `tenancy/middleware.ts` are misconfiguration guards a request cannot
    // reach), so the 500 a caller can actually cause is the unclassified one: a
    // body deep enough to exhaust the stack while it is walked.
    //
    // Depth is escalated rather than pinned because the exact threshold is a
    // workerd/V8 implementation detail; if NONE of these overflow any more the
    // case fails loudly and asks to be re-derived, which is the point.
    let error: APIError | null = null;
    for (const depth of [20_000, 80_000, 320_000]) {
      let content: unknown = "x";
      for (let i = 0; i < depth; i += 1) content = [content];
      const raised = await captured(() =>
        openaiClient().chat.completions.create({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: content as string }],
        }),
      );
      if (raised.status === 500) {
        error = raised;
        break;
      }
    }
    expect(error, "no nesting depth produced a 500 — re-derive this case").not.toBeNull();

    // Still typed — the SDK does not blow up on it.
    expect((error as APIError).constructor.name).toBe("InternalServerError");
    // FLIPPED BY #733. This used to be `text/plain` with the body
    // `Internal Server Error`: `inferenceRouteModule` delegates into an INNER
    // `Hono` that registered no `onError`, so Hono's DEFAULT handler answered
    // and the OUTER `gatewayErrorHandler` never saw a throw at all. `err.code`
    // was `undefined` on the one status where a caller most needs to tell
    // "retry me" from "I am broken".
    expect((error as APIError).code).toBe("internal_error");
    expect((error as APIError).type).toBe("ferrogate_error");
    // The message is a CONSTANT, and deliberately so: the thrown value on this
    // path routinely carries a provider credential, an upstream URL or a stack
    // trace, and none of it is the caller's.
    expect((error as APIError).message).toContain("internal server error");
    // The correlation id is in the body AND in the header, and they agree. It
    // is the only thing a caller can quote in a bug report for this class of
    // failure, so the two diverging would be as bad as it being absent.
    expect((error as APIError).headers?.get("x-request-id")).toEqual(expect.any(String));
    expect((error as APIError).requestID).toEqual(
      ((error as APIError).error as { request_id: string }).request_id,
    );
  });

  it("keeps the envelope shape identical across every status", async () => {
    // One assertion, four statuses: whatever else changes, the four members the
    // SDKs read are always present and always in the same place.
    const cases: Array<{ client: ReturnType<typeof openaiClient>; body: typeof REQUEST }> = [
      { client: openaiClient({ apiKey: "fg_not_a_key" }), body: REQUEST },
      { client: openaiClient({ apiKey: "fg_conformance_tenant_down" }), body: REQUEST },
      { client: openaiClient(), body: { ...REQUEST, model: "no-such-model" } },
    ];

    const shape = {
      message: expect.any(String),
      type: "ferrogate_error",
      code: expect.any(String),
      request_id: expect.any(String),
    };

    for (const { client, body } of cases) {
      const error = await captured(() => client.chat.completions.create(body));
      expect(error.error).toMatchObject(shape);
    }

    // The 5xx leg of the same invariant, and the reason it is worth a separate
    // block: a 502 is originated at a completely different point in the request
    // (after dispatch, in `inference/errors.ts` rather than `middleware/
    // errors.ts`), by a second implementation of the same envelope. The two are
    // byte-compatible today; if either drifts, this goes red.
    const unreachable = interceptUpstream(() => {
      throw new TypeError("Network connection lost.");
    });
    try {
      const dispatchFailure = await captured(() => openaiClient().chat.completions.create(REQUEST));
      expect(dispatchFailure.status).toBe(502);
      expect(dispatchFailure.error).toMatchObject(shape);
    } finally {
      unreachable.restore();
    }
  });

  it("404 — `models.retrieve()` is routed, and an unknown id is a NotFoundError", async () => {
    // RETRACTED DIVERGENCE. This case asserted that `GET /v1/models/{model}`
    // was unrouted and 404'd with the router's generic `not_found` — true when
    // the branch was cut, and #670 landed it while the suite was in review. The
    // assertion going red is what forced this rewrite, which is the entire
    // reason a divergence is pinned as an assertion rather than a comment.
    const model = await openaiClient().models.retrieve("gpt-4o-mini");
    expect(model.id).toBe("gpt-4o-mini");
    expect(model.object).toBe("model");

    // The 404 leg, and the one place FerroGate answers the status an OpenAI
    // client expects for an unknown model: DISCOVERY is 404 `model_not_found`,
    // while INVOCATION of the same unknown model is 400 (see the 400 case
    // above). The two disagree, and both are asserted so the disagreement
    // cannot be lost.
    const error = await captured(() => openaiClient().models.retrieve("no-such-model"));
    expect(error).toBeInstanceOf(NotFoundError);
    expect(error.status).toBe(404);
    expect(error.code).toBe("model_not_found");
    expect(error.message).toContain("no-such-model");
  });
});
