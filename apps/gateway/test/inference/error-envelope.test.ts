/**
 * THE ENVELOPE GUARANTEE (#733) — every 5xx FerroGate is able to write carries
 * the documented `{"error":{message,type,code,request_id}}` body.
 *
 * ## The mechanism, measured rather than assumed
 *
 * Issue #733 reads the `500 text/plain` / `Internal Server Error` answer as
 * "workerd's own error page, because Hono's `onError` never runs". Half right:
 * the outer `onError` really never runs, but the response is not the edge's.
 * `inferenceRouteModule` DELEGATES into an inner `Hono`
 * (`src/inference/route-module.ts:121`) and that inner app registered no error
 * handler, so Hono's DEFAULT one answered —
 *
 *     errorHandler = (err) => { console.error(err); return new Response(
 *       'Internal Server Error', { status: 500 }) }
 *
 * — which is a perfectly ordinary 500 *Response*. The outer app then had
 * nothing to catch: `gatewayErrorHandler` was instrumented and observed ZERO
 * invocations for this request. The distinction matters because it says the
 * failure is fixable in user code (a platform error page would not be), and it
 * says WHERE: at every `new Hono` in the tree, not at the Worker entrypoint.
 *
 * ## What is deliberately NOT covered here
 *
 *  - A throw MID-STREAM, after the 200 and the first bytes are flushed. There
 *    is no envelope to write at that point — the status line is spent — and
 *    the honest answer is to fault the stream so the truncation is visible.
 *    That behaviour is already pinned by
 *    `test/inference/reliability.test.ts:753` ("makes exactly one attempt and
 *    surfaces the fault instead of truncating"), so it is referenced rather
 *    than duplicated.
 *  - The runtime's own limits (CPU time exceeded, isolate OOM). workerd
 *    terminates the isolate; no user code runs, so no test in this process can
 *    assert on the body. A subrequest-limit failure is an ORDINARY throw out of
 *    `fetch` and IS covered — it lands on the same path as case A below.
 */
import { describe, expect, it } from "vitest";
import {
  InMemoryModelResolver,
  createInferenceRouter,
  inferenceRouteModule,
} from "../../src/inference/index.js";
import type { ModelResolver } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, OPENAI_ROUTE, errorBody, fixedRequestIds, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const BASE = "https://gw.test";
const ENV = {
  GATEWAY_STATIC_API_KEYS: JSON.stringify([
    { key: "fg_root", id: "key_root", platform_operator: true },
  ]),
};
const AUTHED = { authorization: "Bearer fg_root", "content-type": "application/json" };
const CHAT = { model: OPENAI_ROUTE.logicalModel, messages: [{ role: "user", content: "hi" }] };

/**
 * A secret shaped like the things this gateway really holds: the provider API
 * key `PhysicalRoute.apiKey` carries, and the D1/R2 binding names. An unhandled
 * throw is the one path where such a value can end up on the wire by accident,
 * because the only thing between an `Error.message` and the client is whatever
 * the error handler chooses to copy.
 */
const SECRET = "sk-live-733-DO-NOT-LEAK";
const BINDING = "CONTROL_DB";
const PROVIDER_URL = "https://api.openai.example/v1/chat/completions";

/** A `ModelResolver` factory that throws while the inner app is resolving deps. */
function exploding(message: string): () => ModelResolver {
  return () => {
    throw new Error(message);
  };
}

/** The deployed composition, with one port replaced. */
function gateway(models: ModelResolver | (() => ModelResolver)) {
  const { app } = createGatewayApp({
    modules: [inferenceRouteModule({ models, requestIds: fixedRequestIds })],
  });
  return (path: string, init?: RequestInit) => app.request(`${BASE}${path}`, init, ENV);
}

// ---------------------------------------------------------------------------
// A. An unhandled throw on the inference path
// ---------------------------------------------------------------------------

describe("an unhandled throw inside the inference router answers the envelope", () => {
  it("is JSON with all four members, not Hono's text/plain default", async () => {
    const call = gateway(exploding("catalog exploded"));
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify(CHAT),
    });

    expect(res.status).toBe(500);
    // The exact byte that used to be wrong: `text/plain; charset=UTF-8`.
    expect(res.headers.get("content-type")).toContain("application/json");

    const body = await errorBody(res);
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.code).toBe("internal_error");
    expect(body.error.request_id).toEqual(expect.any(String));
    // The correlation id in the body and in the header are the SAME value —
    // the only thing a caller can quote in a bug report for this class of
    // failure, and useless if the two disagree.
    expect(res.headers.get("x-request-id")).toBe(body.error.request_id);
  });

  it("never lets the thrown message reach the client", async () => {
    // The whole reason `classifyError`'s unknown arm hard-codes its message.
    // An `Error` raised deep in a provider port routinely carries the
    // credential, the upstream URL or the binding name that failed.
    const call = gateway(
      exploding(`connect ${PROVIDER_URL} with ${SECRET} via ${BINDING} failed`),
    );
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify(CHAT),
    });

    expect(res.status).toBe(500);
    const raw = await res.text();
    expect(raw).not.toContain(SECRET);
    expect(raw).not.toContain(PROVIDER_URL);
    expect(raw).not.toContain(BINDING);
    // No stack trace, by any of its three tells.
    expect(raw).not.toContain("at ");
    expect(raw).not.toContain(".ts:");
    expect(raw).not.toContain("Error:");
    // Still a usable envelope rather than an empty body.
    expect(JSON.parse(raw)).toEqual({
      error: {
        message: "internal server error",
        type: "ferrogate_error",
        code: "internal_error",
        request_id: expect.any(String),
      },
    });
  });

  it("handles a NON-Error thrown value the same way", async () => {
    // `classifyError` reaches its unknown arm through `instanceof` checks, so a
    // thrown string/object/null takes a different branch shape than an `Error`
    // and is exactly the value a `JSON.parse` in a hand-written port throws.
    const call = gateway((() => {
      // A bare literal, never an `Error` — that is the branch under test.
      throw `plain string carrying ${SECRET}`;
    }) as () => ModelResolver);
    const res = await call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify(CHAT),
    });

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toContain("application/json");
    const raw = await res.text();
    expect(raw).not.toContain(SECRET);
    expect((JSON.parse(raw) as { error: { code: string } }).error.code).toBe("internal_error");
  });

  it("is produced by the INNER router itself, not only by the outer mount", async () => {
    // Driving `createInferenceRouter` directly — the shape every other file in
    // this directory uses — proves the guarantee belongs to the router and does
    // not depend on `createGatewayApp` wrapping it. If the handler were
    // registered on the outer app only, this case stays red.
    const router = createInferenceRouter({
      models: exploding("catalog exploded"),
      requestIds: fixedRequestIds,
    });
    const res = await router.request(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(CHAT),
    });

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect((await errorBody(res)).error.code).toBe("internal_error");
  });
});

// ---------------------------------------------------------------------------
// B. An unparseable UPSTREAM error body
// ---------------------------------------------------------------------------

describe("an upstream error body that is not JSON is wrapped, not relayed", () => {
  it("answers the FerroGate envelope for a CDN's HTML 502", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response(
          "<html><head><title>502 Bad Gateway</title></head><body>bad gateway</body></html>",
          { status: 502, headers: { "content-type": "text/html; charset=utf-8" } },
        ),
    );
    try {
      const app = harness();
      const res = await app.post("/v1/chat/completions", CHAT);

      // The STATUS is the upstream's, deliberately: a 502 is retryable and a
      // 500 is not, and collapsing both to one number would delete the only
      // distinction a caller has. Only the unusable BODY is replaced.
      expect(res.status).toBe(502);
      expect(res.headers.get("content-type")).toContain("application/json");

      const body = await errorBody(res);
      expect(body.error.type).toBe("ferrogate_error");
      expect(body.error.code).toBe("provider_invalid_error_body");
      expect(body.error.request_id).toEqual(expect.any(String));
      // MEANINGFUL, not `internal_error`: it names what happened (the provider
      // answered an error the gateway could not parse) and carries the status
      // and media type, which is everything a caller can act on.
      expect(body.error.message).toContain("502");
      expect(body.error.message).toContain("text/html");
    } finally {
      provider.restore();
    }
  });

  it("does not echo the upstream's markup back to the caller", async () => {
    // The relay used to put the provider's bytes on the wire verbatim. For an
    // error page from a load balancer those bytes are worthless to a client AND
    // are the one place an upstream can push its own internals through this
    // gateway (server banners, internal hostnames, request-id headers embedded
    // in the page).
    const provider = interceptProviderFetch(
      () =>
        new Response(`<html>backend ${PROVIDER_URL} rejected key ${SECRET}</html>`, {
          status: 503,
          headers: { "content-type": "text/html" },
        }),
    );
    try {
      const res = await harness().post("/v1/chat/completions", CHAT);
      expect(res.status).toBe(503);
      const raw = await res.text();
      expect(raw).not.toContain(SECRET);
      expect(raw).not.toContain(PROVIDER_URL);
      expect(raw).not.toContain("<html>");
    } finally {
      provider.restore();
    }
  });

  it("still relays a JSON provider error VERBATIM — the taxonomy must survive", async () => {
    // The complement, and the reason the wrap is conditional rather than
    // universal: a provider error object is the caller's best diagnostic, and
    // `tools/sdk-conformance/test/errors.test.ts:152` pins that `err.type` /
    // `err.param` reach the SDK unchanged. Wrapping everything would have made
    // this file green and that one red.
    const provider = interceptProviderFetch(() =>
      providerJson(
        { error: { message: "Unrecognized argument", type: "invalid_request_error", param: "foo" } },
        400,
      ),
    );
    try {
      const res = await harness().post("/v1/chat/completions", CHAT);
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { type: string; param: string } };
      expect(body.error.type).toBe("invalid_request_error");
      expect(body.error.param).toBe("foo");
    } finally {
      provider.restore();
    }
  });

  it("leaves a SUCCESSFUL non-JSON upstream body alone", async () => {
    // The wrap is scoped to error statuses. A 2xx body the gateway passes
    // through byte-for-byte (`/v1/embeddings`, `/v1/images`) must not be
    // touched by an error-shaped rule.
    const provider = interceptProviderFetch(
      () =>
        new Response("not json but perfectly fine", {
          status: 200,
          headers: { "content-type": "text/plain" },
        }),
    );
    try {
      const res = await harness().post("/v1/embeddings", {
        model: "text-embed",
        input: "hello",
      });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("not json but perfectly fine");
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// C. Anti-drift: no Hono app in this Worker may fall back to Hono's default
// ---------------------------------------------------------------------------

describe("every Hono app the gateway builds registers an error handler", () => {
  it("is asserted at the SOURCE, because a new inner app is how this returns", async () => {
    // The behavioural cases above cover the two apps that exist TODAY. This one
    // covers the app someone adds tomorrow: the defect was never "the inference
    // router forgot", it was "delegating into a bare `new Hono` silently opts
    // out of the envelope", and nothing but a source-level gate sees that
    // before it ships.
    const sources = import.meta.glob("../../src/**/*.ts", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;

    const offenders: string[] = [];
    for (const [path, source] of Object.entries(sources)) {
      if (!/new Hono</.test(source)) continue;
      if (!/\.onError\(/.test(source)) offenders.push(path);
    }
    expect(offenders, "a Hono app with no onError answers text/plain on a throw").toEqual([]);
  });

  it("keeps the inner router's model resolver injectable, so this file is honest", () => {
    // Guards the fixture itself: if `models` stopped being a factory seam the
    // cases above would stop reaching the code they claim to reach.
    expect(() => createInferenceRouter({ models: new InMemoryModelResolver(ALL_ROUTES) })).not.toThrow();
  });
});
