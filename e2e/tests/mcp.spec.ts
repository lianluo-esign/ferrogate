/**
 * JSON-RPC 2.0 envelope round-trip against a REAL `wrangler dev` running
 * `apps/mcp`'s own `wrangler.toml` and `src/index.ts`.
 *
 * ## What this layer can and cannot reach
 *
 * `apps/mcp/wrangler.toml` sets `FG_DEV_IN_MEMORY_PORTS = "1"`, so `resolvePorts`
 * installs the in-memory bundle and `/readyz` reports ready. But that bundle's
 * `InMemoryAuth` starts with an EMPTY key table which only an in-process test
 * can seed (`inMemoryPorts().auth.register(...)`) — there is no var, no binding
 * and no HTTP surface that registers one. A black-box client therefore CANNOT
 * obtain a credential, and every authenticated JSON-RPC method is unreachable
 * from here by design.
 *
 * That is not a gap this file papers over: the codec's parse/validate stage runs
 * BEFORE authentication, so the whole JSON-RPC 2.0 envelope contract — version
 * literal, id echo, omitted members, reserved error codes — is fully assertable
 * unauthenticated, and it is asserted below. The authenticated `tools/list` →
 * `result` leg stays with layer 1 (`apps/mcp/test/jsonrpc.test.ts`), which can
 * seed a key.
 *
 * PORT-TODO(inventory-edge-control §MCP): when the D1/KV/Secrets-Store-backed
 * auth port lands, `wrangler dev --var`/`.dev.vars` will be able to supply a key
 * the way `gateway.spec.ts` already does, and an authenticated round-trip
 * (`tools/list` → `{ jsonrpc, id, result }`) belongs here.
 */
import { expect, test } from "@playwright/test";

import { type JsonRpcResponseBody, MCP_BASE_URL, type McpHttpErrorEnvelope } from "../fixtures.js";

const RPC_URL = `${MCP_BASE_URL}/v1/mcp`;
const JSON_HEADERS = { "content-type": "application/json" };

/**
 * Post a RAW body. Playwright serializes an object `data` to JSON, which is
 * exactly what these cases must not do — several of them are testing bodies
 * that are not valid JSON at all, or are valid JSON that is not an object.
 *
 * The body MUST be a `Buffer`, not a `string`: with `content-type:
 * application/json` Playwright JSON-ENCODES a string `data`, so the truncated
 * body `{"jsonrpc":"2.0",` left here as a string reached the Worker as the
 * quoted literal `"{\"jsonrpc\":\"2.0\","` — valid JSON (a string), which the
 * Worker correctly answered `-32600 Invalid Request` instead of the `-32700`
 * parse error this file asserts. A `Buffer` is transmitted verbatim, so the
 * bytes on the wire are the bytes written here. (Verified against a real
 * `wrangler dev`: the same truncated bytes via curl answer `-32700`.)
 */
type RawPost = { headers: Record<string, string>; data: Buffer };
const raw = (body: string): RawPost => ({ headers: JSON_HEADERS, data: Buffer.from(body, "utf8") });

test.describe("mcp liveness", () => {
  test("GET /healthz reports the service and pinned protocol revision", async ({ request }) => {
    const res = await request.get(`${MCP_BASE_URL}/healthz`);

    expect(res.status()).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      service: "ferrogate-mcp",
      runtime: "workers",
      protocol: "2026-07-28",
    });
  });

  test("GET /readyz is ready because the dev port bundle is bound", async ({ request }) => {
    // `readinessReport` answers 503 `not_ready` when `portsBound(env)` is false,
    // so a 200 here proves `FG_DEV_IN_MEMORY_PORTS` really reached the isolate
    // through wrangler's own config load — not just through a test fixture.
    const res = await request.get(`${MCP_BASE_URL}/readyz`);

    expect(res.status()).toBe(200);
    expect(await res.json()).toMatchObject({
      status: "ready",
      service: "ferrogate-mcp",
      dependencies: { ready: true },
    });
  });
});

test.describe("mcp JSON-RPC 2.0 envelope", () => {
  test("unparseable JSON is -32700 Parse error in a valid 2.0 envelope", async ({ request }) => {
    // A raw truncated body — it must reach the Worker as bytes that are NOT
    // valid JSON, so it cannot go through Playwright's object serializer.
    const res = await request.post(RPC_URL, raw('{"jsonrpc":"2.0",'));

    // JSON-RPC transports its own failures in the body; the HTTP hop succeeded.
    expect(res.status()).toBe(200);

    const body = (await res.json()) as JsonRpcResponseBody;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error?.code).toBe(-32700);
    expect(typeof body.error?.message).toBe("string");
    // Exactly one of result/error, and `id` is OMITTED (never null) when it
    // could not be determined — the `skip_serializing_if` parity note in
    // `apps/mcp/src/jsonrpc.ts`.
    expect(body).not.toHaveProperty("result");
    expect(body).not.toHaveProperty("id");
  });

  test("a wrong `jsonrpc` literal is -32600 Invalid Request, with the id echoed", async ({
    request,
  }) => {
    const res = await request.post(RPC_URL, {
      headers: JSON_HEADERS,
      data: { jsonrpc: "1.0", id: "e2e-invalid-version", method: "tools/list" },
    });

    expect(res.status()).toBe(200);

    const body = (await res.json()) as JsonRpcResponseBody;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error?.code).toBe(-32600);
    // The id is recoverable here, so the spec REQUIRES it be echoed — this is
    // what lets a client correlate the failure with its request.
    expect(body.id).toBe("e2e-invalid-version");
    expect(body).not.toHaveProperty("result");
  });

  test("a missing `jsonrpc` member is -32600, not silently accepted", async ({ request }) => {
    // Deliberate tightening over Rust, which declared `jsonrpc: Option<String>`
    // and never checked it. Documented in `apps/mcp/src/jsonrpc.ts`.
    const res = await request.post(RPC_URL, {
      headers: JSON_HEADERS,
      data: { id: 1, method: "tools/list" },
    });

    expect(res.status()).toBe(200);

    const body = (await res.json()) as JsonRpcResponseBody;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error?.code).toBe(-32600);
    expect(body.id).toBe(1);
  });

  test("every non-object / structurally invalid body is -32600 Invalid Request", async ({
    request,
  }) => {
    // JSON-RPC 2.0 distinguishes "could not be parsed" (-32700) from "parsed,
    // but is not a Request object" (-32600). Each row below IS valid JSON, so
    // every one must land on -32600 — collapsing them onto -32700 would be a
    // codec regression that a single happy-path test would never catch.
    const malformed: ReadonlyArray<{ label: string; body: string; id?: string | number }> = [
      { label: "array body", body: "[1,2,3]" },
      { label: "scalar string body", body: '"just-a-string"' },
      { label: "number body", body: "42" },
      { label: "null body", body: "null" },
      { label: "empty object", body: "{}" },
      { label: "no method member", body: '{"jsonrpc":"2.0","id":3}', id: 3 },
      { label: "non-string method", body: '{"jsonrpc":"2.0","id":4,"method":42}', id: 4 },
    ];

    for (const { label, body: payload, id } of malformed) {
      const res = await request.post(RPC_URL, raw(payload));

      expect(res.status(), `${label}: HTTP hop succeeds`).toBe(200);
      const body = (await res.json()) as JsonRpcResponseBody;
      expect(body.jsonrpc, `${label}: envelope version`).toBe("2.0");
      expect(body.error?.code, `${label}: Invalid Request`).toBe(-32600);
      expect(body, `${label}: must not also carry a result`).not.toHaveProperty("result");

      if (id === undefined) {
        // Unrecoverable id ⇒ the member is OMITTED, never serialized as null.
        expect(body, `${label}: id omitted`).not.toHaveProperty("id");
      } else {
        expect(body.id, `${label}: id echoed`).toBe(id);
      }
    }
  });
});

test.describe("mcp transport guards", () => {
  test("a well-formed request with no credential is a 401 HTTP refusal", async ({ request }) => {
    // The envelope stage passed (the body is valid JSON-RPC); the refusal comes
    // from the auth port, and it is an HTTP-level error, NOT a JSON-RPC one —
    // an unauthenticated caller is not an RPC peer yet.
    const res = await request.post(RPC_URL, {
      headers: JSON_HEADERS,
      data: { jsonrpc: "2.0", id: "e2e-anon", method: "tools/list" },
    });

    expect(res.status()).toBe(401);
    const body = (await res.json()) as McpHttpErrorEnvelope;
    expect(body.error.code).toBe("unauthenticated");
    expect(body).not.toHaveProperty("jsonrpc");
  });

  test("an unrecognised bearer is 401 invalid_api_key", async ({ request }) => {
    const res = await request.post(RPC_URL, {
      headers: { ...JSON_HEADERS, authorization: "Bearer fg_not_a_real_key" },
      data: { jsonrpc: "2.0", id: "e2e-badkey", method: "tools/list" },
    });

    expect(res.status()).toBe(401);
    expect(((await res.json()) as McpHttpErrorEnvelope).error.code).toBe("invalid_api_key");
  });

  test("GET /v1/mcp is 405 — the JSON-RPC endpoint is POST-only", async ({ request }) => {
    const res = await request.get(RPC_URL);

    expect(res.status()).toBe(405);
    expect(((await res.json()) as McpHttpErrorEnvelope).error.code).toBe("method_not_allowed");
  });

  test("an unmapped method still answers a well-formed 2.0 envelope", async ({ request }) => {
    const res = await request.post(RPC_URL, {
      headers: JSON_HEADERS,
      data: { jsonrpc: "2.0", id: "e2e-unknown-method", method: "totally/unknown" },
    });

    const body = (await res.json()) as JsonRpcResponseBody;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe("e2e-unknown-method");
    expect(Number.isInteger(body.error?.code)).toBe(true);
    expect(body).not.toHaveProperty("result");

    // The exact code/status is NOT pinned here on purpose. A method the contract
    // carries no scope mapping for currently surfaces as `-32603` with HTTP 500,
    // which is very likely wrong: JSON-RPC's answer for an unknown method is
    // `-32601 Method not found`, and the gateway's own
    // `middleware/auth.ts` PORT-TODO already flags this exact case. Asserting
    // 500/-32603 would cement the suspected defect; asserting the envelope
    // invariants holds the behavior that is definitely right, and this test
    // starts failing the moment the shape regresses.
    // PORT-TODO(inventory-edge-control §MCP): once the unmapped-method answer is
    // settled (-32601 vs a 403), tighten this to the exact code.
  });
});
