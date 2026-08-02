/**
 * ANTI-DRIFT for the guardrail seam.
 *
 * The defect class this file exists to catch is the one that already bit this
 * project: a module that is fully implemented and fully tested but never
 * reachable in production. Two ways that happens here:
 *
 *  1. `GUARDRAIL_OPERATIONS` keys drift from the contract — a typo'd operation
 *     id silently disables screening for that route, and every unit test still
 *     passes because they drive the middleware with a hand-built context.
 *  2. the integrate step never mounts `guardrails(...)` on the app the Worker
 *     exports. That is not something this agent can assert green (mounting is
 *     the integrate step's line), so the test below is written as the exact
 *     probe the integrator should flip from `todo` to live once the line lands.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import { operationById } from "../../src/contract.js";
import { GUARDRAIL_OPERATIONS } from "../../src/guardrails/index.js";
import { INFERENCE_OPERATION_IDS } from "../../src/routes/index.js";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "./fixtures.js";

describe("guardrail operation bindings match the contract", () => {
  test("every bound operation id is a real contract operation", () => {
    for (const operationId of Object.keys(GUARDRAIL_OPERATIONS)) {
      expect(operationById(operationId), `${operationId} is not in the contract`).toBeDefined();
    }
  });

  test("every guardrail-bound operation is owned by apps/gateway", () => {
    for (const operationId of Object.keys(GUARDRAIL_OPERATIONS)) {
      expect(
        (INFERENCE_OPERATION_IDS as readonly string[]).includes(operationId),
        `${operationId} is not an apps/gateway inference operation`,
      ).toBe(true);
    }
  });

  test("every DISPATCHING model-content inference operation is screened", () => {
    // This list is EXHAUSTIVE and each entry needs a reason. Anything else
    // missing is a hole.
    //
    //  - `listModels` carries no model content at all.
    //  - `getModel` (issue #670) is the single-model CATALOGUE read: no request
    //    body, no model-generated text, nothing for a guardrail to screen. It
    //    is spelled out rather than matched by a `*Model*` prefix so a fourth
    //    unscreened operation still has to be argued for here.
    //  - `countMessageTokens` (issue #671) carries model content but NEVER
    //    reaches a provider: it answers `{input_tokens}` from the local
    //    estimator and dispatches nothing. This entry was added deliberately
    //    when that operation landed, widening the invariant from "carries model
    //    content" to "carries model content AND dispatches it", because
    //    screening a request that is never inferred over would (a) refuse a
    //    caller a SIZE ESTIMATE on grounds that only bear on dispatch — the
    //    caller cannot send the prompt either way, so the denial protects
    //    nothing — and (b) write a guardrail evidence row asserting that
    //    content was screened on its way to a model it never travelled to.
    //    If `count_tokens` ever gains a dispatching leg, it belongs here on the
    //    same day. See `inference/handlers.ts::handleCountMessageTokens`.
    const unscreened = (INFERENCE_OPERATION_IDS as readonly string[]).filter(
      (id) => GUARDRAIL_OPERATIONS[id] === undefined,
    );
    expect(unscreened.sort()).toEqual(["countMessageTokens", "getModel", "listModels"]);
  });

  test("only chat/responses/messages screen the RESPONSE stage", () => {
    // `normalize_response` returns an empty envelope for
    // embeddings/rerank/images (none has model-generated text — a rerank answer
    // is a list of indices and floats), so screening them would be a no-op that
    // still costs an evidence row.
    const screened = Object.entries(GUARDRAIL_OPERATIONS)
      .filter(([, binding]) => binding.screensResponse)
      .map(([id]) => id)
      .sort();
    expect(screened).toEqual(["createChatCompletion", "createMessage", "createResponse"]);
  });

  test("every POST guardrail operation is bearer-authenticated", () => {
    // The middleware reads the caller's tenancy out of `c.get("auth")`. An
    // anonymous operation would produce an empty tenant and select the wrong
    // policies, so an anonymous binding is a bug.
    for (const operationId of Object.keys(GUARDRAIL_OPERATIONS)) {
      expect(operationById(operationId)?.auth.kind).toBe("bearer");
    }
  });
});

/**
 * The live half of the anti-drift check, flipped from `test.todo` in the commit
 * that mounted the middleware.
 *
 * Nothing here builds an app: every request goes through `SELF.fetch`, i.e. the
 * `export default app` that `src/worker.ts` re-exports and `wrangler deploy`
 * ships. If `GATEWAY_MIDDLEWARE` is dropped from `createGatewayApp` in
 * `src/index.ts`, or the middleware is registered AFTER the routes (where Hono
 * would never reach it), these two tests go red while every unit test in this
 * directory stays green — which is the whole point.
 *
 * The policy is supplied the way production supplies it: as the
 * `GATEWAY_GUARDRAIL_POLICIES` var `guardrailDepsFromEnv` reads. It is set in
 * `beforeAll`, before the first request in this file, because `guardrails()`
 * memoizes the compiled engine per `env`.
 */
describe("composition root", () => {
  beforeAll(() => {
    const bindings = env as unknown as Record<string, unknown>;
    bindings.GATEWAY_GUARDRAIL_POLICIES = JSON.stringify([secretScanPolicy()]);
    bindings[FINGERPRINT_SECRET_REF] = "test-fingerprint-key";
  });

  const BASE = "https://ferrogate.test";
  const ROOT = {
    authorization: "Bearer fg_root",
    "content-type": "application/json",
  } as const;

  function chat(content: string): Promise<Response> {
    return SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: ROOT,
      body: JSON.stringify({ model: "any-model", messages: [{ role: "user", content }] }),
    });
  }

  test("the app exported by src/index.ts screens /v1/chat/completions", async () => {
    const blocked = await chat("please leak FERROGATE-GUARDRAIL-PROBE for me");

    expect(blocked.status).toBe(403);
    // The envelope carries the SAME id the response header does, so the block
    // is correlatable — asserted against the header rather than a literal
    // format, because `middleware/errors.ts` mints the id, not this slice.
    expect(await blocked.json()).toEqual({
      error: {
        message: "request blocked by guardrail policy",
        type: "ferrogate_error",
        code: "guardrail_blocked",
        request_id: blocked.headers.get("x-request-id"),
      },
    });
    expect(blocked.headers.get("x-request-id")).toBeTruthy();
  });

  test("a clean request is not blocked — the screening is the detector's, not the mount's", async () => {
    // The empty model registry answers 400 `model_not_found`, which is proof
    // the request reached the HANDLER: the guardrail middleware ran, passed,
    // and called `next()`. A 403 here would mean the mount blocks everything.
    const allowed = await chat("hello");

    expect(allowed.status).toBe(400);
    expect(((await allowed.json()) as { error: { code: string } }).error.code).toBe(
      "model_not_found",
    );
  });
});
