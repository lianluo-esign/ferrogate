/**
 * The Hono middleware seam, driven through the EXACT wiring the integrate step
 * is instructed to install (`src/guardrails/index.ts` §WIRING):
 *
 *   app.use("*", contractAuth(deps));      // the real contract guard
 *   app.use("*", guardrails(deps));        // <- this module
 *   ...route modules
 *
 * `contractAuth` is imported from `src/middleware/auth.ts` — the production
 * guard, not a stand-in — so the middleware is exercised against the real
 * `c.get("operation")` / `c.get("auth")` / `c.get("requestId")` variables it
 * will see in the deployed Worker.
 *
 * NOTE FOR THE INTEGRATOR: the guardrail middleware is NOT yet mounted on the
 * app `src/index.ts` exports. `test/guardrails/wiring.test.ts` asserts the
 * facts that make the wiring above correct (operation ids exist in the contract
 * and belong to this Worker); mounting is the integrate step's single line.
 */
import { env } from "cloudflare:test";
import { Hono } from "hono";
import { describe, expect, test } from "vitest";
import { depsFromEnv } from "../../src/adapters.js";
import {
  type GuardrailAuditEvent,
  InMemoryGuardrailEvidenceSink,
  guardrails,
} from "../../src/guardrails/index.js";
import { contractAuth } from "../../src/middleware/auth.js";
import { gatewayErrorHandler, requestId } from "../../src/middleware/errors.js";
import type { GatewayEnv } from "../../src/ports.js";
import { GatewayRouter } from "../../src/routes/index.js";
import {
  EVIDENCE_HMAC_KEY,
  PROBE_SECRET,
  bodyWithProbeSecret,
  cleanBody,
  failingDetector,
  secretScanPolicy,
  sourceFor,
} from "./fixtures.js";

// Static operator key from `vitest.config.ts` — all scopes, so the ONLY thing
// standing between the request and the route is the guardrail middleware.
const KEY = "fg_root";

interface Harness {
  readonly app: Hono<GatewayEnv>;
  readonly evidence: InMemoryGuardrailEvidenceSink;
  readonly audit: GuardrailAuditEvent[];
}

/**
 * Assemble the app the way `createGatewayApp` does, with the guardrail
 * middleware in the documented slot and a stub upstream handler standing in for
 * the inference route module (which this agent does not own).
 */
function harness(options: {
  policy?: ReturnType<typeof secretScanPolicy>;
  detectorOverrides?: Parameters<typeof sourceFor>[1];
  upstream?: () => Response;
}): Harness {
  const evidence = new InMemoryGuardrailEvidenceSink();
  const audit: GuardrailAuditEvent[] = [];
  const app = new Hono<GatewayEnv>();
  app.onError(gatewayErrorHandler);
  app.use("*", requestId);
  app.use("*", contractAuth(depsFromEnv));
  app.use(
    "*",
    guardrails({
      policies: sourceFor(options.policy ?? secretScanPolicy(), options.detectorOverrides ?? {}),
      evidence,
      evidenceHmacKey: EVIDENCE_HMAC_KEY,
      audit: { record: (event) => void audit.push(event) },
      providerForModel: () => "openai",
    }),
  );
  const router = new GatewayRouter(app);
  router.register(
    "createChatCompletion",
    options.upstream ??
      (() =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-1",
            choices: [{ index: 0, message: { role: "assistant", content: "all good" } }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )),
  );
  router.register("listModels", () => new Response(JSON.stringify({ data: [] }), { status: 200 }));
  return { app, evidence, audit };
}

function post(body: unknown, path = "/v1/chat/completions"): Request {
  return new Request(`https://gateway.test${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("input screening through the middleware", () => {
  test("a prompt carrying a secret gets the Rust 403 envelope", async () => {
    const { app, audit } = harness({});
    const response = await app.fetch(post(bodyWithProbeSecret()), env);

    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toBe("application/json");
    const body = await response.json();
    expect(body).toEqual({
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
        // Whatever `middleware/errors.ts::requestId` minted for this request —
        // the guardrail envelope echoes it, it is never null.
        request_id: expect.any(String),
      },
    });
    // Serde declaration order is preserved on the wire.
    expect(Object.keys((body as { error: object }).error)).toEqual([
      "message",
      "type",
      "code",
      "request_id",
    ]);
    expect(audit.some((event) => event.action === "guardrail.deny")).toBe(true);
  });

  test("the upstream handler is never reached on a block", async () => {
    let reached = false;
    const { app } = harness({
      upstream: () => {
        reached = true;
        return new Response("{}", { status: 200 });
      },
    });
    await app.fetch(post(bodyWithProbeSecret()), env);
    expect(reached).toBe(false);
  });

  test("a clean prompt reaches the upstream untouched", async () => {
    const { app } = harness({});
    const response = await app.fetch(post(cleanBody()), env);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("all good");
  });

  test("the middleware does NOT consume the body the route still needs", async () => {
    // A `Request.clone()` read must leave the original stream intact — otherwise
    // the inference module's own bounded read would see an empty body.
    let seen: unknown;
    const { app } = harness({
      upstream: () =>
        new Response(JSON.stringify({ choices: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    const app2 = app;
    const router = new GatewayRouter(app2);
    router.register("createResponse", async (c) => {
      seen = await c.req.raw.json();
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    await app2.fetch(post(cleanBody(), "/v1/responses"), env);
    expect(seen).toEqual(cleanBody());
  });

  test("a detector outage blocks the request (FAIL CLOSED, end to end)", async () => {
    const { app } = harness({ detectorOverrides: { deterministic: failingDetector("timeout") } });
    const response = await app.fetch(post(cleanBody()), env);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "guardrail_provider_unavailable",
    );
  });

  test("an operation with no guardrail binding is untouched", async () => {
    const { app, evidence } = harness({});
    const response = await app.fetch(
      new Request("https://gateway.test/v1/models", {
        headers: { authorization: `Bearer ${KEY}` },
      }),
      env,
    );
    expect(response.status).toBe(200);
    expect(evidence.evaluations()).toHaveLength(0);
  });

  test("an unauthenticated request is refused BEFORE the body is screened", async () => {
    const { app, evidence } = harness({});
    const response = await app.fetch(
      new Request("https://gateway.test/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(bodyWithProbeSecret()),
      }),
      env,
    );
    expect(response.status).toBe(401);
    // The guardrail never ran: auth precedes it, exactly as `chat.rs:158` requires.
    expect(evidence.evaluations()).toHaveLength(0);
  });
});

describe("output screening through the middleware", () => {
  const responseRedact = secretScanPolicy({
    policyId: "response-redact",
    stage: "response",
    onFail: [{ kind: "redact", code: "guardrail_redacted", message: "redacted" }],
  });

  test("a completion carrying a secret is redacted in place", async () => {
    const { app, audit } = harness({
      policy: responseRedact,
      upstream: () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-1",
            choices: [
              { index: 0, message: { role: "assistant", content: `key ${PROBE_SECRET} ok` } },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });
    const response = await app.fetch(post(cleanBody()), env);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain(PROBE_SECRET);
    expect(text).toContain("[REDACTED]");
    expect(audit.some((event) => event.action === "guardrail.redact")).toBe(true);
  });

  test("a completion carrying a secret is BLOCKED when the policy says block", async () => {
    const { app } = harness({
      policy: secretScanPolicy({ policyId: "response-block", stage: "response" }),
      upstream: () =>
        new Response(
          JSON.stringify({
            choices: [{ index: 0, message: { role: "assistant", content: PROBE_SECRET } }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });
    const response = await app.fetch(post(cleanBody()), env);
    expect(response.status).toBe(403);
    const text = await response.text();
    expect(text).not.toContain(PROBE_SECRET);
    expect(JSON.parse(text).error.code).toBe("guardrail_blocked");
  });

  test("a provider ERROR body is not screened as model content", async () => {
    const { app, evidence } = harness({
      policy: secretScanPolicy({ policyId: "response-block", stage: "response" }),
      upstream: () =>
        new Response(JSON.stringify({ error: { message: PROBE_SECRET } }), {
          status: 429,
          headers: { "content-type": "application/json" },
        }),
    });
    const response = await app.fetch(post(cleanBody()), env);
    // The provider's own error object reaches the caller unchanged.
    expect(response.status).toBe(429);
    expect(evidence.evaluations().filter((row) => row.stage === "response")).toHaveLength(0);
  });

  test("an SSE completion is screened incrementally, not buffered", async () => {
    const frames = [
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "safe " } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: PROBE_SECRET } }] })}\n\n`,
      "data: [DONE]\n\n",
    ];
    const { app } = harness({
      policy: secretScanPolicy({ policyId: "stream-block", stage: "response" }),
      upstream: () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              const encoder = new TextEncoder();
              for (const frame of frames) {
                controller.enqueue(encoder.encode(frame));
              }
              controller.close();
            },
          }),
          { status: 200, headers: { "content-type": "text/event-stream" } },
        ),
    });
    const response = await app.fetch(post({ ...cleanBody(), stream: true }), env);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    const text = await response.text();
    expect(text).toContain("safe ");
    expect(text).not.toContain(PROBE_SECRET);
    expect(text).toContain("guardrail_blocked");
  });

  test("reject_streaming refuses a streaming request with 403 before dispatch", async () => {
    let reached = false;
    const { app } = harness({
      policy: secretScanPolicy({ policyId: "no-stream", streaming: "reject_streaming" }),
      upstream: () => {
        reached = true;
        return new Response("{}", { status: 200 });
      },
    });
    const response = await app.fetch(post({ ...cleanBody(), stream: true }), env);
    expect(response.status).toBe(403);
    expect(JSON.parse(await response.text()).error.code).toBe("guardrail_streaming_unsupported");
    expect(reached).toBe(false);
  });
});

describe("body handling", () => {
  test("a non-JSON body is left to the downstream reader's invalid_json", async () => {
    let reached = false;
    const { app, evidence } = harness({
      upstream: () => {
        reached = true;
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      },
    });
    const response = await app.fetch(
      new Request("https://gateway.test/v1/chat/completions", {
        method: "POST",
        headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
        body: "{not json",
      }),
      env,
    );
    expect(reached).toBe(true);
    expect(response.status).toBe(200);
    expect(evidence.evaluations()).toHaveLength(0);
  });

  test("an over-cap body is left to the downstream reader's payload_too_large", async () => {
    let reached = false;
    const { app, evidence } = harness({
      upstream: () => {
        reached = true;
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      },
    });
    const huge = {
      model: "gpt-4o",
      messages: [{ role: "user", content: `${PROBE_SECRET}${"x".repeat(200)}` }],
    };
    const app2 = new Hono<GatewayEnv>();
    app2.onError(gatewayErrorHandler);
    app2.use("*", requestId);
    app2.use("*", contractAuth(depsFromEnv));
    app2.use(
      "*",
      guardrails({
        policies: sourceFor(secretScanPolicy()),
        evidence,
        maxRequestBytes: 16,
      }),
    );
    new GatewayRouter(app2).register("createChatCompletion", () => {
      reached = true;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const response = await app2.fetch(post(huge), env);
    // The guardrail declined to screen; the ROUTE decides (here the stub 200,
    // in production `readInferenceBody`'s 413).
    expect(reached).toBe(true);
    expect(response.status).toBe(200);
    expect(evidence.evaluations()).toHaveLength(0);
    void app;
  });
});
