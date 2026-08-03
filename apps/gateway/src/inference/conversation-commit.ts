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
 * PERSIST AFTER THE RESPONSE STAGE **AND** SCREEN THE READ — NOT EITHER/OR
 * ============================================================================
 *
 * This block used to be headed "the choice", and framing the two as
 * ALTERNATIVES is what let a false clause stand in the guardrail wiring test for
 * two audit rounds. They are complements. Each covers something the other
 * cannot, and #689 ships both.
 *
 * **Persisting after the response stage** (this module) is the primary fix, and
 * it is the only one that reaches three of the four legs:
 *
 *  - a DENIED turn is never written, so there is nothing at rest for the
 *    retention window, nothing to read back and nothing to replay. A read-time
 *    screen would leave those bytes on disk for hours;
 *  - a REDACTED turn is filed redacted, so a same-credential continuation
 *    replays the redacted transcript upstream — the egress the policy exists to
 *    stop. Doing that at read time instead would mean re-screening every prior
 *    turn on every continuation: O(depth) detector work, including PAID detector
 *    calls, on every turn of every conversation;
 *  - screening is paid ONCE, on the write.
 *
 * **Screening `GET /v1/responses/{id}`** (`guardrails/middleware.ts`, the
 * `getResponse` binding) covers the leg this module cannot see, because it is
 * about WHO is reading rather than WHAT was written. Conversation state is
 * fenced on `(tenantId, projectId)`; guardrail policy scope is fenced per KEY.
 * So a turn written by an UNGOVERNED credential is correctly stored verbatim and
 * then served, verbatim, to a GOVERNED credential of the same project whose own
 * policy would have redacted it. The read is O(1) — one stored document, one
 * pass, on a request that infers nothing — so the cost argument above does not
 * apply to it at all.
 *
 * The cost of persist-after, stated: a policy that TIGHTENS after a turn was
 * stored does not retroactively apply to the bytes on disk. For the credential
 * that WROTE the turn that is the right trade — it already holds the text, so a
 * retroactive refusal protects nothing — and for any OTHER credential the read
 * binding above re-decides under that reader's own live policy.
 *
 * ============================================================================
 * CROSS-KEY CONTINUATIONS (#779)
 * ============================================================================
 *
 * This module still does not screen a continuation: it cannot, because the
 * chain is assembled inside the inner inference router. The router now closes
 * that leg at the assembly point:
 *
 *  - every row records the API-key id under which this delivered turn was
 *    screened;
 *  - the guardrail middleware publishes its already-resolved engine as a
 *    request-scoped replay capability; and
 *  - `handlers.ts::prepareConversation` re-decides stored input and output under
 *    the continuing key only when that id differs.
 *
 * The cost is therefore O(foreign turns), and zero detector work for same-key
 * conversations. The stored row remains byte-for-byte what its writer received;
 * replay screening works on a clone and never rewrites shared state.
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
 * would silently disable conversation state, so `test/guardrails/wiring.test.ts`
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
