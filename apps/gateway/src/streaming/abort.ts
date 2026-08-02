/**
 * Client-disconnect -> upstream-abort propagation.
 *
 * In the Rust tower this was implicit: the async pump owned the
 * `reqwest::Response`, and dropping the upstream (`StreamingBodySource`) closed
 * the provider connection — "Dropping the upstream aborts the provider
 * connection (client-disconnect propagation)"
 * (`docs/legacy/inventory-request-path.md` §1.5). Workers has no drop
 * semantics, so the same guarantee has to be wired explicitly:
 *
 *   client goes away  ->  the `Response` body `ReadableStream` is cancelled
 *                     ->  {@link abortOnCancel} fires the `AbortController`
 *                     ->  the provider `fetch()` (given that controller's
 *                         signal) is aborted, so we stop paying for tokens
 *                         nobody will read.
 *
 * Without this the provider keeps generating — and keeps billing — for a
 * request whose client hung up, which is a real cost-leak class, not a nicety.
 */

/** Reason attached to an abort caused by the client hanging up. */
export const CLIENT_DISCONNECT_REASON = "client disconnected before the provider stream completed";

/** Build an `AbortError`-shaped reason (`DOMException` where available). */
export function abortReason(message: string = CLIENT_DISCONNECT_REASON): unknown {
  if (typeof DOMException === "function") {
    return new DOMException(message, "AbortError");
  }
  const error = new Error(message);
  error.name = "AbortError";
  return error;
}

/**
 * Forward an abort from `source` to `target`.
 *
 * Fires synchronously when `source` is already aborted (a client that
 * disconnected before we even dispatched must not cause an upstream call), and
 * returns an unsubscribe function so a completed request does not leak a
 * listener on a long-lived signal.
 */
export function linkAbortSignal(
  source: AbortSignal | undefined,
  target: AbortController,
  reason?: unknown,
): () => void {
  if (source === undefined) {
    return () => {};
  }
  if (source.aborted) {
    target.abort(reason ?? source.reason ?? abortReason());
    return () => {};
  }
  const onAbort = (): void => {
    target.abort(reason ?? source.reason ?? abortReason());
  };
  source.addEventListener("abort", onAbort, { once: true });
  return () => {
    source.removeEventListener("abort", onAbort);
  };
}

/** An upstream abort handle: one controller, plus its client-signal linkage. */
export interface UpstreamAbort {
  /** Pass this to the provider `fetch()`. */
  readonly signal: AbortSignal;
  /** Abort the upstream explicitly (guardrail veto, budget exhaustion, ...). */
  abort(reason?: unknown): void;
  /** True once aborted. */
  readonly aborted: boolean;
  /** Detach the client-signal listener. */
  dispose(): void;
}

/**
 * Create the controller that governs the upstream provider call, pre-linked to
 * the inbound request's signal.
 */
export function createUpstreamAbort(clientSignal?: AbortSignal): UpstreamAbort {
  const controller = new AbortController();
  const unlink = linkAbortSignal(clientSignal, controller);
  return {
    signal: controller.signal,
    abort(reason?: unknown) {
      if (!controller.signal.aborted) {
        controller.abort(reason ?? abortReason());
      }
    },
    get aborted(): boolean {
      return controller.signal.aborted;
    },
    dispose: unlink,
  };
}

/**
 * Anything that can be aborted: a real `AbortController`, or the
 * {@link UpstreamAbort} handle above. Keeping this structural means the
 * cancellation plumbing does not care which one it was handed.
 */
export interface Abortable {
  abort(reason?: unknown): void;
  readonly signal?: AbortSignal;
  readonly aborted?: boolean;
}

function isAborted(target: Abortable): boolean {
  return target.signal?.aborted ?? target.aborted ?? false;
}

/**
 * Wrap a stream so that cancelling it aborts `controller`.
 *
 * `TransformStream` alone is not enough: the cancellation the Workers runtime
 * delivers when a client disconnects arrives on the *readable* end, and it must
 * be turned into an `AbortController.abort()` on the upstream `fetch`. Normal
 * completion (the upstream closing first) does NOT abort.
 */
export function abortOnCancel<T>(
  source: ReadableStream<T>,
  controller: Abortable,
  reason?: unknown,
): ReadableStream<T> {
  const reader = source.getReader();
  return new ReadableStream<T>({
    async pull(target) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          target.close();
          return;
        }
        target.enqueue(value);
      } catch (error) {
        target.error(error);
      }
    },
    async cancel(cancelReason) {
      if (!isAborted(controller)) {
        controller.abort(reason ?? cancelReason ?? abortReason());
      }
      try {
        await reader.cancel(cancelReason);
      } catch {
        // The upstream may already be torn down; the abort above is what
        // actually stops the provider.
      }
    },
  });
}

/** Options for {@link dispatchStreamingUpstream}. */
export interface StreamingUpstreamOptions {
  /** Provider endpoint. */
  readonly url: string;
  /** Fetch init; any `signal` here is replaced by the managed one. */
  readonly init?: Omit<RequestInit, "signal">;
  /** The inbound client request's signal (`request.signal` in a Worker). */
  readonly clientSignal?: AbortSignal;
  /** Injection seam for tests / for the AI Gateway binding's `fetch`. */
  readonly fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>;
}

/** A dispatched provider stream plus the handle that can kill it. */
export interface StreamingUpstream {
  readonly response: Response;
  /** The provider body, wrapped so client cancellation aborts the fetch. */
  readonly body: ReadableStream<Uint8Array> | null;
  readonly abort: UpstreamAbort;
}

/**
 * Dispatch a streaming provider request with disconnect propagation wired end
 * to end. The returned `body` is the stream to normalize and hand back to the
 * client; cancelling it (which the runtime does on disconnect) aborts the
 * provider fetch.
 */
export async function dispatchStreamingUpstream(
  options: StreamingUpstreamOptions,
): Promise<StreamingUpstream> {
  const abort = createUpstreamAbort(options.clientSignal);
  const doFetch = options.fetchImpl ?? ((input: string, init?: RequestInit) => fetch(input, init));
  let response: Response;
  try {
    response = await doFetch(options.url, { ...options.init, signal: abort.signal });
  } catch (error) {
    abort.dispose();
    throw error;
  }
  const raw = response.body as ReadableStream<Uint8Array> | null;
  const body = raw === null ? null : abortOnCancel(raw, abort);
  return { response, body, abort };
}
