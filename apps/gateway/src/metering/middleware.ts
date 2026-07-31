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
 */
import type { MiddlewareHandler } from "hono";
import type { UsageRecordContext } from "../inference/ports.js";
import type { GatewayEnv } from "../ports.js";
import { executionContextOf } from "./runtime.js";
import type { MeteringUsageSink } from "./sink.js";

/** Responses whose usage frame lands AFTER the headers are flushed. */
function isEventStream(response: Response): boolean {
  return (response.headers.get("content-type") ?? "").includes("text/event-stream");
}

/**
 * Wrap a body so `settled` resolves once the client has either finished it or
 * abandoned it — and, in the abandon case, only after the cancel has propagated
 * all the way up through the usage tap.
 */
function observeBodyCompletion(body: ReadableStream<Uint8Array>): {
  readonly body: ReadableStream<Uint8Array>;
  readonly settled: Promise<void>;
} {
  const reader = body.getReader();
  let resolve: () => void = () => undefined;
  const settled = new Promise<void>((done) => {
    resolve = done;
  });

  const wrapped = new ReadableStream<Uint8Array>({
    async pull(controller): Promise<void> {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          controller.close();
          resolve();
          return;
        }
        controller.enqueue(chunk.value);
      } catch (error) {
        // The upstream broke. Whatever the tap scraped before it broke is still
        // a real charge, so settle rather than stranding the outbox.
        controller.error(error);
        resolve();
      }
    },
    async cancel(reason): Promise<void> {
      try {
        // Awaited: this is what runs the usage tap's `cancel()` and therefore
        // what makes the consumed-tokens charge exist before the drain looks.
        await reader.cancel(reason);
      } finally {
        resolve();
      }
    },
  });

  return { body: wrapped, settled };
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

    const ctx = executionContextOf(c);
    const rc: UsageRecordContext = { env: c.env, ctx };

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
