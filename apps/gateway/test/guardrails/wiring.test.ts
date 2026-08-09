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
import { normalizeRequest, normalizeResponse } from "@ferrogate/guardrails";
import { beforeAll, describe, expect, test } from "vitest";
import { operationById } from "../../src/contract.js";
import { GUARDRAIL_OPERATIONS } from "../../src/guardrails/index.js";
import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
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
    //  - the two audio uploads (issue #703) were briefly on this list, on the
    //    argument that a `multipart/form-data` body wrapping opaque audio has
    //    nothing a detector can read. That argument is still true, and it is
    //    still the reason `screensRequest` is `false` for them below — but it
    //    only covers the INPUT. A transcription's ANSWER is text, chosen by
    //    whoever supplied the recording, handed to a caller who will usually put
    //    it in the next prompt. So they are bound after all, at the response
    //    stage, and the list is back to the three operations that carry no
    //    dispatched model content at all.
    const unscreened = (INFERENCE_OPERATION_IDS as readonly string[]).filter(
      (id) => GUARDRAIL_OPERATIONS[id] === undefined,
    );
    //  - `deleteResponse` (issue #689) carries no content in EITHER direction:
    //    no request body, and a `{id, object, deleted}` envelope — an id, a
    //    literal type tag and a boolean — back. Nothing a detector can read at
    //    either stage, which is the same reason `listModels` and `getModel` are
    //    on this list and not the reason `countMessageTokens` is. The
    //    justification is deliberately about THIS operation alone.
    //
    //    `getResponse` is NOT here, and the two attempts it took are worth
    //    recording because the argument is subtle and both wrong versions were
    //    green. Attempt one: "already screened and already delivered to this
    //    same credential once" — false for the exactly two cases an exception
    //    has to survive, since a REDACTED turn was stored un-redacted and a
    //    DENIED turn was never delivered at all. That was fixed at the WRITE
    //    (`src/inference/conversation-commit.ts` files the screened bytes), and
    //    attempt two rested on the repaired half: "a byte the response stage
    //    approved and this credential already holds". The first clause became
    //    true; the second never was. Conversation state is fenced on
    //    `(tenantId, projectId)` while policy scope is fenced per KEY
    //    (`api_key_ids`, the narrowest selector `packages/guardrails/src/
    //    policy.ts` ranks), so one project's two credentials share one store
    //    under different policies and an UNGOVERNED key's turn was served to a
    //    GOVERNED one, verbatim. So it is bound at the response stage, which is
    //    O(1) — one stored document, one pass, on a request that infers
    //    nothing. `test/inference/responses-cross-key-guardrail.test.ts` is the
    //    measurement, both directions.
    //
    //    The write-side fix stays load-bearing and is asserted immediately
    //    below: it is what keeps a DENIED turn off disk entirely, and what keeps
    //    a continuation from replaying un-screened text upstream. The behaviour
    //    is measured end to end in
    //    `test/inference/responses-guardrail-bypass.test.ts`.
    expect(unscreened.sort()).toEqual([
      "countMessageTokens",
      "deleteResponse",
      "getModel",
      "listModels",
    ]);
  });

  test("the #689 conversation WRITE is mounted above the response stage", () => {
    // The half of #689's guardrail story that cannot be read off
    // `GUARDRAIL_OPERATIONS` at all: WHERE the turn is written relative to the
    // screener. Binding `getResponse` does not make this redundant — the two are
    // complements. This mount is what keeps a DENIED turn off disk (there is no
    // row for a read to screen) and what keeps a same-credential continuation
    // from replaying un-redacted text upstream; the binding is what covers a
    // read by a credential the writer's policy did not govern.
    //
    // Hono is an onion, so a middleware registered EARLIER wraps the ones after
    // it and its post-`next()` work runs LAST. `responseStateCommit()` therefore
    // has to sit at a SMALLER index than `guardrails()` to see the screened
    // body. At a larger index it would file the pre-screening bytes and
    // `getResponse` would hand back content the operator's policy redacted or
    // refused — which is precisely the shape #689 first shipped, with this file
    // green because it asserted the exception and not the reason for it.
    //
    // Reordering is the one defect no behavioural test can see (a correctly
    // ordered and a merely present mount both serve the happy path identically),
    // so it is asserted structurally, by runtime handler name, exactly as
    // `test/metering/wiring.test.ts` pins the billing drain.
    const names = GATEWAY_MIDDLEWARE.map((handler) => handler.name);
    expect(names).toContain("responseStateCommitMiddleware");
    expect(names).toContain("guardrailsMiddleware");
    expect(names.indexOf("responseStateCommitMiddleware")).toBeLessThan(
      names.indexOf("guardrailsMiddleware"),
    );
  });

  test("the RESPONSE stage runs for chat/responses/messages, the transcripts and the stored read", () => {
    // `normalize_response` returns an empty envelope for
    // embeddings/rerank/images/speech (none has screenable text output — a
    // rerank answer is a list of indices and floats, a speech answer is an
    // MP3), so screening them would be a no-op that still costs an evidence
    // row. The two audio uploads are here because their answer IS text, and
    // `normalize (audio_transcription)` in `packages/guardrails/test/
    // envelope.test.ts` pins that it walks to a non-empty envelope.
    //
    // `getResponse` (#689) is here because its answer is a stored TURN — a real
    // completion — and the credential reading it need not be the credential
    // whose policy approved it. See the unscreened list above.
    const screened = Object.entries(GUARDRAIL_OPERATIONS)
      .filter(([, binding]) => binding.screensResponse)
      .map(([id]) => id)
      .sort();
    expect(screened).toEqual([
      "createChatCompletion",
      "createMessage",
      "createResponse",
      "createTranscription",
      "createTranslation",
      "getResponse",
    ]);
  });

  test("only bodiless requests skip the request stage", () => {
    // `screensRequest: false` is a real hole in input control and it must never
    // become the easy way to make a binding compile. The only justification this
    // table accepts is "there is no text here for a detector to read", and it is
    // true of exactly three operations for two reasons: `multipart/form-data`
    // wrapping opaque audio (#703), and a GET with no body at all (#689).
    // Anything else appearing in this list is an operation whose prompt stopped
    // being screened, which is the defect the whole file exists to catch.
    //
    // For `getResponse` the flag is also FORCED rather than chosen: with
    // `screensRequest: true` the middleware's `readJsonBodyBounded` returns
    // `undefined` for a null body and the branch answers with an early
    // `return next()`, which would skip the RESPONSE stage too and leave the
    // binding inert — a control that reads as present and enforces nothing.
    const unscreenedInput = Object.entries(GUARDRAIL_OPERATIONS)
      .filter(([, binding]) => !binding.screensRequest)
      .map(([id]) => id)
      .sort();
    expect(unscreenedInput).toEqual(["createTranscription", "createTranslation", "getResponse"]);

    // And the forcing itself, so the paragraph above is an assertion rather
    // than a claim: every request-skipping binding must screen the RESPONSE,
    // because a binding that skips both stages is a no-op entry.
    for (const [id, binding] of Object.entries(GUARDRAIL_OPERATIONS)) {
      if (!binding.screensRequest) {
        expect(binding.screensResponse, `${id} screens neither stage`).toBe(true);
      }
    }
  });

  test("no binding is a NO-OP: every stage a binding claims can produce content", () => {
    // The anti-vacuity gate, and the reason it is structural rather than an
    // end-to-end case per operation. A binding whose protocol normalizes to an
    // EMPTY envelope screens nothing, passes every check, still writes an
    // evidence row and still reports a `guardrail_verdict` — a control that
    // reads as present and enforces nothing. That failure is silent, so it is
    // pinned here against a representative body for each stage a binding claims.
    const REQUEST_BODY: Record<string, unknown> = {
      model: "m",
      // chat / responses / messages
      messages: [{ role: "user", content: "hello" }],
      // responses
      input: "hello",
      // embeddings
      // (`input` above doubles for it)
      // rerank
      query: "hello",
      documents: ["a document"],
      // images
      prompt: "a picture of a cat",
    };
    const RESPONSE_BODY = new TextEncoder().encode(
      JSON.stringify({
        // chat
        choices: [{ message: { role: "assistant", content: "an answer" } }],
        // responses
        output: [{ content: [{ type: "output_text", text: "an answer" }] }],
        // audio_transcription
        text: "an answer",
      }),
    );
    for (const [id, binding] of Object.entries(GUARDRAIL_OPERATIONS)) {
      if (binding.screensRequest) {
        expect(
          normalizeRequest(binding.protocol, REQUEST_BODY).segments.length,
          `${id} claims request screening over an empty envelope`,
        ).toBeGreaterThan(0);
      }
      if (binding.screensResponse) {
        expect(
          normalizeResponse(binding.protocol, RESPONSE_BODY, false).segments.length,
          `${id} claims response screening over an empty envelope`,
        ).toBeGreaterThan(0);
      }
    }
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
