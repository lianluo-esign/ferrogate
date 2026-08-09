/**
 * `meteringDrain()` — the middleware that owns the durable half of metering.
 *
 * ## Why a middleware, and not `record()` itself
 *
 * `MeteringUsageSink.record` does the CPU-bound half synchronously (build the
 * billing event → price it → convert to integer credits → capture in the
 * outbox) and must never do I/O inline: it is called from the SSE tap's
 * `flush()`/`cancel()`, i.e. after the response headers and most of the body
 * have already gone to the client. The durable half therefore has to run on
 * `ctx.waitUntil`, which is the only thing on Workers that keeps an isolate's
 * I/O alive after a response is flushed. Everything else — a bare floating
 * promise, a `setTimeout`, a module-scoped queue — may have its `IoContext`
 * torn down mid-write, and the symptom is a charge that silently never landed.
 *
 * This middleware is where the request's `ExecutionContext` and `env` are in
 * scope at the same time, so it is where the drain belongs.
 *
 * ## The streaming problem, and the exact fix
 *
 * For a BUFFERED response the tap has already recorded usage by the time
 * `await next()` returns, so draining right there is correct.
 *
 * For an SSE response it has NOT: the usage frame is the second-to-last event
 * on the wire, so at `await next()` the charge does not exist yet, and a drain
 * scheduled then would find an empty outbox and persist nothing. The stream
 * also has two different endings that must BOTH meter:
 *
 *  - it runs to completion → the tap's `flush()` reports the final usage frame;
 *  - the CLIENT HANGS UP mid-stream → the tap's `cancel()` reports whatever was
 *    consumed. Billing nothing here is the cost leak `src/streaming/abort.ts`
 *    exists to close; billing the trailing frame would be billing tokens nobody
 *    received.
 *
 * So an SSE body is wrapped in a pull-driven passthrough that settles a promise
 * on *either* ending, and the drain is chained onto that promise inside
 * `ctx.waitUntil`. The wrapper is deliberately NOT `pipeTo` — `pipeTo` rejects
 * on a destination cancel and calls `source.cancel()` concurrently, so the
 * drain could race ahead of the tap's `cancel()` and find nothing to persist.
 * Reading through an explicit `ReadableStream` source lets the `cancel` hook
 * AWAIT `reader.cancel(reason)`, which awaits the tap's `cancel()`, which is
 * what makes "disconnect mid-stream still meters" deterministic rather than
 * lucky. It adds no buffering: `pull` reads exactly one upstream chunk per
 * downstream demand, so backpressure and first-token latency are unchanged.
 *
 * That wrapper now lives in `../middleware/body-completion.ts` rather than
 * here, because the request-log writer (#664) needs the identical property for
 * the identical reason — its token counts come from the same tap. It was MOVED,
 * not reimplemented: a second copy of a stream-lifetime primitive is how the
 * two diverge on the disconnect path, which is the leg nobody exercises by
 * hand. The disconnect cases in `test/metering/durable.test.ts` still hold this
 * behaviour from the money side.
 */
import type { Context, MiddlewareHandler } from "hono";
import { isEventStream, observeBodyCompletion } from "../middleware/body-completion.js";
import type { AuthContext, GatewayEnv } from "../ports.js";
import { tenantDatabaseOf } from "../tenancy/middleware.js";
import { AGENT_RUN_ID_HEADER, agentRunIdFor } from "./agent-run.js";
import { executionContextOf } from "./runtime.js";
import type { MeteringUsageSink } from "./sink.js";
import type { MeteringAttribution, MeteringDrainContext } from "./usage-ledger.js";

/**
 * Who this request's usage is attributed to, from the authenticated credential.
 *
 * This is the ONLY place the api-key id is available to metering: `Usage`
 * (`src/inference/ports.ts`) does not carry one, and that file belongs to the
 * composition root rather than to this slice. Without it
 * `tenant_contexts.api_key_id` is never written, and
 * `sumApiKeyCommittedTokens` — the operand of `api_keys.monthly_token_budget` —
 * sums zero forever. See `./usage-ledger.ts` for why it is guarded by request
 * id when it is applied.
 *
 * `undefined` for an anonymous operation, which meters nothing anyway.
 *
 * `requestId` is supplied by the caller rather than read from
 * `c.get("requestId")`, and that is load-bearing: the inference handlers run
 * inside the INNER Hono app `inferenceRouteModule` delegates into, which mints
 * its OWN id (`inference/handlers.ts:781`) unless the client sent an inbound
 * `x-request-id`. The id a charge carries is therefore the INNER one, and the
 * outer variable would never match it. See {@link meteringDrain} for where the
 * matching id comes from.
 */
export function attributionFrom(
  c: Context<GatewayEnv>,
  requestId: string,
): MeteringAttribution | undefined {
  const auth = c.get("auth") as AuthContext | null | undefined;
  if (auth === null || auth === undefined) return undefined;
  const { tenantId, projectId, workspaceId } = auth.tenancy;
  // #305/#522 — the agent run that caused this spend. Read off the REQUEST for
  // the same reason the api-key id is read off the credential: `Usage` carries
  // neither, and this middleware is the only place either is in scope. See
  // `./agent-run.ts` for why a malformed value is dropped rather than carried.
  const agentRunId = agentRunIdFor(c.req.header(AGENT_RUN_ID_HEADER));
  return {
    requestId,
    ...(tenantId === null || tenantId === undefined ? {} : { tenantId }),
    ...(projectId === null || projectId === undefined ? {} : { projectId }),
    ...(workspaceId === null || workspaceId === undefined ? {} : { workspaceId }),
    ...(auth.subject === null ? {} : { apiKeyId: auth.subject }),
    ...(agentRunId === undefined ? {} : { agentRunId }),
  };
}

/**
 * Cross-cutting middleware that flushes the metering outbox on
 * `ctx.waitUntil`, after the response (or the whole stream) has been served.
 *
 * Mount it FIRST in `GATEWAY_MIDDLEWARE` so it is the outermost of the
 * cross-cutting handlers and therefore sees the final `Response`.
 *
 * Draining is idempotent and cheap when there is nothing to do (an empty outbox
 * returns on the first `listDue`), so running it on every request — including
 * the ones that meter nothing — costs a comparison and buys the property that
 * a charge left behind by an earlier request whose drain failed is retried by
 * the next one. That is the Rust sweeper's behaviour, expressed as request-time
 * work because a Worker has no background thread.
 */
export function meteringDrain(sink: MeteringUsageSink): MiddlewareHandler<GatewayEnv> {
  return async function meteringDrainMiddleware(c, next): Promise<void> {
    await next();

    /**
     * The id the CHARGE will carry.
     *
     * `inference/handlers.ts:695` stamps its own `requestId` onto the response,
     * and `middleware/errors.ts:191` only fills the header in when it is
     * absent — so the response header is the inner id for a metered request and
     * the outer id for everything else. That is exactly the id
     * `MeteringUsageSink` files the charge under, which is what makes the
     * request-id guard in `./usage-ledger.ts` able to match at all.
     */
    const requestId = c.res.headers.get("x-request-id") ?? c.get("requestId") ?? "";
    const attribution = attributionFrom(c, requestId);
    let usageDatabase: D1Database | null | undefined;
    if (attribution?.tenantId !== undefined) {
      try {
        usageDatabase = await tenantDatabaseOf(c).db();
      } catch {
        usageDatabase = null;
      }
    }

    const ctx = executionContextOf(c);
    const rc: MeteringDrainContext = {
      env: c.env,
      ctx,
      ...(attribution?.tenantId === undefined ? {} : { usageDatabase }),
      ...(attribution === undefined ? {} : { attribution }),
    };

    // No `ExecutionContext` (a unit test's `app.request()`): the sink's own
    // scheduler is the only lifetime available, and `flush` never rejects.
    if (ctx === undefined) {
      void sink.flush(rc);
      return;
    }

    const response = c.res;
    const body = response.body;
    if (body === null || !isEventStream(response)) {
      ctx.waitUntil(sink.flush(rc));
      return;
    }

    const observed = observeBodyCompletion(body);
    c.res = new Response(observed.body, response);
    ctx.waitUntil(observed.settled.then(() => sink.flush(rc)));
  };
}
