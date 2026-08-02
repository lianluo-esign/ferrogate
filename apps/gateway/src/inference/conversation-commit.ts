/**
 * WHERE THE `/v1/responses` TURN IS ACTUALLY WRITTEN (issue #689).
 *
 * ============================================================================
 * WHY THE WRITE CANNOT LIVE IN THE INFERENCE ROUTER
 * ============================================================================
 *
 * The inference handlers run inside a SEPARATE Hono app that
 * `inference/route-module.ts` delegates into, and the guardrail RESPONSE stage
 * (`guardrails/middleware.ts`) runs one layer OUT, on the way back. So the bytes
 * the handler holds are PRE-SCREENING: the copy the operator's policy has not
 * yet redacted, and — the case that makes this a security boundary rather than a
 * consistency nicety — the copy it is about to REFUSE outright.
 *
 * Persisting there and serving the row back from `GET /v1/responses/{id}` meant:
 *
 *  - a REDACT policy delivered `[REDACTED:…]` to the caller and filed the
 *    original, which the same credential could then read back verbatim;
 *  - a DENY policy delivered `403 guardrail_blocked` and filed the whole answer
 *    the caller was never allowed to see;
 *  - and a continuation replayed the un-redacted transcript back UPSTREAM as
 *    `input`, which is the egress the redact policy exists to prevent, performed
 *    by the gateway itself.
 *
 * ============================================================================
 * THE CHOICE: PERSIST AFTER THE RESPONSE STAGE, NOT SCREEN ON THE READ
 * ============================================================================
 *
 * Both close the reported hole. They are not equivalent:
 *
 *  - **Screening on the read** leaves the refused bytes AT REST for the whole
 *    retention window and leaves the chain replay unscreened — a continuation
 *    would still hand the provider content the policy redacted, unless every
 *    continuation re-screened every prior turn, which is O(depth) detector work
 *    (including PAID detector calls) on every turn of every conversation.
 *  - **Persisting after the response stage** writes exactly the bytes the caller
 *    received. Screening is paid ONCE, on the write, and the read is free. A
 *    denied turn is never written, so there is nothing to retain, nothing to
 *    read back, and nothing to replay.
 *
 * The cost of the choice, stated: a policy that TIGHTENS after a turn was stored
 * does not retroactively apply to it. That is the right trade here and it is the
 * same argument the `getResponse` guardrail exception rests on — the caller
 * already holds those exact bytes, because they were delivered, so a retroactive
 * refusal protects nothing. It is only a sound argument BECAUSE of this module:
 * with a pre-screening row it would have been false for both cases that matter.
 *
 * ============================================================================
 * THE SEAM
 * ============================================================================
 *
 * The handler publishes a PENDING turn keyed by the inbound `Request` — the same
 * `WeakMap`-by-`Request` carrier `requestlog/facts.ts` and `inference/identity.ts`
 * already use to cross the inner/outer app boundary, chosen there for the same
 * reasons (a module-scoped "current request" slot is a cross-request leak the
 * moment two requests interleave on an `await`, and a wrapper `env` would defeat
 * the by-`env` memoization the model registry and the guardrail engine rely on).
 *
 * {@link responseStateCommit} is the middleware that redeems it. It is mounted
 * OUTSIDE `guardrails()` in `src/index.ts`, so by the time its `await next()`
 * returns the response stage has already redacted, refused or passed the body,
 * and what it reads is byte-for-byte what the client is about to receive.
 *
 * FAIL-CLOSED if it is ever unmounted: the pending turn is simply never
 * redeemed, nothing is stored, `x-ferrogate-response-stored` stays `false`, and
 * the next `previous_response_id` refuses loudly with
 * `previous_response_not_found`. Unmounting cannot resurrect the bypass — but it
 * would silently disable conversation state, so `test/inference/wiring.test.ts`
 * pins the mount AND its position relative to `guardrails()`.
 */
import type { Context, MiddlewareHandler, Next } from "hono";
import type { GatewayEnv } from "../ports.js";
import type { CapturedResponseOutput } from "./conversation-capture.js";
import { responsesOutputTap } from "./conversation-capture.js";
import { RESPONSE_STORED_HEADER } from "./conversation.js";

/**
 * One turn that has been DECIDED but not yet written.
 *
 * Both commits are closures built by `inference/handlers.ts` over the resolved
 * store, the plan and the logical model, so no policy leaves that module: this
 * one owns only WHEN the write happens and WHICH bytes it sees.
 *
 * Neither ever throws — see `handlers.ts::persistTurn` for why a storage failure
 * after a billed provider call is reported through the header rather than by
 * destroying the completion.
 */
export interface PendingConversationTurn {
  /** The gateway id this turn will be known by (already on the response headers). */
  readonly responseId: string;
  /**
   * Persist a BUFFERED answer: the exact JSON document the client receives,
   * parsed. `approximateBytes` is the length of those same bytes.
   */
  commitBuffered(body: Record<string, unknown>, approximateBytes: number): Promise<boolean>;
  /** Persist a STREAMED answer, assembled from the frames the client receives. */
  commitStreamed(captured: CapturedResponseOutput): Promise<boolean>;
}

const PENDING = new WeakMap<Request, PendingConversationTurn>();

/**
 * Announce that this request produced a turn to be written once the response
 * stage has settled.
 *
 * Called from the inference handler with the OUTER inbound `Request`
 * (`c.get("inferenceOriginRequest")`), which is the object
 * `route-module.ts` handed to `inner.fetch` and the object the middleware below
 * sees as `c.req.raw`.
 */
export function publishPendingTurn(request: Request, pending: PendingConversationTurn): void {
  PENDING.set(request, pending);
}

/** The turn awaiting a write for this request, if any. */
export function pendingTurnFor(request: Request): PendingConversationTurn | undefined {
  return PENDING.get(request);
}

/**
 * `c.executionCtx` THROWS on a context built without one (every `app.request(…)`
 * in a test), and the only use here is `waitUntil`.
 */
function executionCtxOf(c: Context<GatewayEnv>): Context<GatewayEnv>["executionCtx"] | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

/**
 * Write the pending `/v1/responses` turn from the CLIENT-VISIBLE response.
 *
 * NAMED, not an arrow, for the same reason `guardrailsMiddleware` is: the mount
 * and its ORDER are asserted structurally by runtime handler name, and an
 * anonymous handler is invisible to that gate — which is how a reordering, the
 * one defect no behavioural test can see, would slip through.
 */
export function responseStateCommit(): MiddlewareHandler<GatewayEnv> {
  return async function responseStateCommitMiddleware(c: Context<GatewayEnv>, next: Next) {
    // Read BEFORE `next()`: the inner app re-presents `c.req.raw` while reading
    // the body, so the identity has to be captured while it is still the object
    // the outer chain (and `route-module.ts`) keyed everything else by.
    const inbound = c.req.raw;
    await next();

    const pending = pendingTurnFor(inbound);
    if (pending === undefined) {
      // Every request that is not a storing `/v1/responses` call: one WeakMap
      // lookup and nothing else. The body is not read, cloned or replaced.
      return;
    }
    const response = c.res;
    if (response === undefined || response.body === null) {
      return;
    }
    if (response.status >= 400) {
      // The client was REFUSED — by the guardrail response stage, by the
      // envelope boundary, by anything above. There is no delivered answer, so
      // there is no turn. This one branch is what keeps denied content off disk.
      return;
    }

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("text/event-stream")) {
      // The tap goes on the FINAL stream — the one `screenSseBody` has already
      // redacted or cut short — so what is assembled is what the client read.
      // The chunks are re-enqueued as the same `Uint8Array` references, so
      // first-token latency is unchanged (see `conversation-capture.ts`).
      //
      // The header is settled optimistically here, which is the best any
      // streamed answer can do: the headers are flushed before the first token,
      // long before the last frame that decides whether the write succeeds.
      response.headers.set(RESPONSE_STORED_HEADER, "true");
      const tapped = response.body.pipeThrough(
        responsesOutputTap((captured) => {
          const work = pending.commitStreamed(captured);
          const executionCtx = executionCtxOf(c);
          if (executionCtx !== undefined) {
            executionCtx.waitUntil(work);
            return;
          }
          // No `waitUntil` (unit tests): the write is already in flight and the
          // commit never rejects, so nothing is lost and nothing escapes.
          void work;
        }),
      );
      c.res = new Response(tapped, response);
      return;
    }

    // Buffered. CLONED rather than consumed: the client's `Response` object is
    // left exactly as the response stage produced it, so nothing here can change
    // the bytes, the status or the content type. The clone costs one copy of a
    // body the inner router had already buffered in full, and only on a request
    // that asked to store.
    let stored = false;
    try {
      const text = await response.clone().text();
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        stored = await pending.commitBuffered(
          parsed as Record<string, unknown>,
          new TextEncoder().encode(text).byteLength,
        );
      }
    } catch {
      // A body that is not readable JSON is not a turn: filing it would produce
      // a chain whose replay is empty. `stored` stays false and the header says
      // so, which is the loud half of the contract.
      stored = false;
    }
    // Mutated IN PLACE. Assigning `c.res` here would be wrong: Hono's setter
    // copies the OLD response's headers over the new one, so the freshly decided
    // value would be overwritten by the placeholder the handler wrote.
    response.headers.set(RESPONSE_STORED_HEADER, stored ? "true" : "false");
  };
}
