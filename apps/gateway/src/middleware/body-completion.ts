/**
 * "The client has finished this body, or given up on it" — as a promise.
 *
 * ## Why anything needs this
 *
 * Two cross-cutting concerns on this gateway have to do their work AFTER a
 * streamed response is over rather than when its headers were flushed:
 *
 *  - metering (`src/metering/middleware.ts`): the usage frame is the
 *    second-to-last event on an SSE wire, so at `await next()` the charge does
 *    not exist yet and a drain scheduled there would persist nothing;
 *  - the request log (`src/requestlog/middleware.ts`): the token counts arrive
 *    from the same tap, so a row written at header time would record a
 *    streamed inference request with no tokens.
 *
 * Both also have to handle the SECOND ending, which is the one that gets
 * forgotten: the CLIENT HANGS UP mid-stream. Billing nothing there is a cost
 * leak; logging nothing there loses the record of a request that really
 * happened and really cost money.
 *
 * ## Why this is not `pipeTo`
 *
 * `pipeTo` rejects on a destination cancel and calls `source.cancel()`
 * concurrently, so a task chained onto it can race AHEAD of the usage tap's own
 * `cancel()` and find nothing recorded. Reading through an explicit
 * `ReadableStream` lets the `cancel` hook AWAIT `reader.cancel(reason)`, which
 * awaits the tap, which is what makes "disconnect mid-stream still records"
 * deterministic rather than lucky.
 *
 * It adds no buffering: `pull` reads exactly one upstream chunk per downstream
 * demand, so backpressure and first-token latency are unchanged. Wrapping twice
 * (metering and the request log both observe the same response) therefore costs
 * one extra pull hop per chunk and no memory.
 *
 * Extracted from `src/metering/middleware.ts`, where it lived first and where
 * its behaviour is pinned by the disconnect cases in
 * `test/metering/durable.test.ts`.
 */

export interface ObservedBody {
  /** The body to hand back to the client, in place of the original. */
  readonly body: ReadableStream<Uint8Array>;
  /** Resolves once the client has finished the body, or abandoned it. */
  readonly settled: Promise<void>;
}

/** Wrap a body so `settled` resolves on EITHER ending. */
export function observeBodyCompletion(body: ReadableStream<Uint8Array>): ObservedBody {
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
        // The upstream broke. Whatever was scraped before it broke is still
        // real, so settle rather than stranding the observer.
        controller.error(error);
        resolve();
      }
    },
    async cancel(reason): Promise<void> {
      try {
        // Awaited: this is what runs the usage tap's `cancel()` and therefore
        // what makes the consumed-token facts exist before the observer looks.
        await reader.cancel(reason);
      } finally {
        resolve();
      }
    },
  });

  return { body: wrapped, settled };
}

/** True for a response whose facts land AFTER the headers are flushed. */
export function isEventStream(response: Response): boolean {
  return (response.headers.get("content-type") ?? "").includes("text/event-stream");
}
