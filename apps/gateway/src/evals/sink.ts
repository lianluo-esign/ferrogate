/**
 * The PRODUCER half — a sampled exchange leaves the request isolate here, and
 * this is the last thing in this slice that runs anywhere near a client.
 *
 * ```
 *   onlineEvaluation()                       [middleware.ts]
 *     └── ctx.waitUntil(sink.enqueue(sample, { env }))
 *            └── env.ONLINE_EVAL bound? → Queue.send(wire)
 *                else                   → counted `dropped`, and nothing else
 * ```
 *
 * ## Why there is no direct-judge fallback, unlike `requestlog/sink.ts`
 *
 * The request-log sink has a second arm that writes to D1 inline when no queue
 * is bound, because the work it is deferring is one INSERT. The work this sink
 * defers is a PAID MODEL CALL of unbounded latency. Running it inside the
 * request's own `waitUntil` would keep the isolate alive for the length of a
 * judge inference on every sampled request, and a Worker's CPU/wall budget is
 * charged against that invocation — an evaluation feature that quietly doubles
 * the isolate lifetime of 5% of traffic is a cost regression discovered on an
 * invoice.
 *
 * So an unqueued deployment evaluates NOTHING, and says so through
 * {@link OnlineEvalSink.stats}. "No scores" and "no queue" must not look
 * identical, which is the same reasoning #664 gives for counting its own drops.
 *
 * ## Every failure here is a counter, never an exception
 *
 * `enqueue` never rejects. It is called from inside `ctx.waitUntil` after the
 * response object exists, so a rejection could only surface as a logged Worker
 * exception on a request that succeeded — and an observability feature that
 * makes a served request look failed is worse than one that measures nothing.
 */
import { type OnlineEvalSample, onlineEvalSampleToWire } from "./record.js";

/**
 * `[[queues.producers]] binding = "ONLINE_EVAL"`, structurally. A live `Queue`
 * satisfies it with no cast, so nothing in production names a test double.
 */
export interface OnlineEvalQueue {
  send(body: unknown, options?: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>, options?: unknown): Promise<void>;
}

/** What the producer has done since the isolate started. */
export interface OnlineEvalStats {
  /** Samples handed to the Queue producer. */
  readonly queued: number;
  /** Samples with nowhere to go — no `ONLINE_EVAL` binding. */
  readonly dropped: number;
  /** Sends that were attempted and rejected. */
  readonly failed: number;
  /**
   * Requests considered and not sampled, by reason. This is the map that makes
   * an empty score table diagnosable: `not_opted_in` is a configuration answer,
   * `zero_data_retention` is a deliberate exclusion, `not_in_sample` is the
   * sampler working, and `policy_unreadable` is a bug to fix.
   */
  readonly skipped: Readonly<Record<string, number>>;
}

export interface OnlineEvalSinkBindings {
  readonly ONLINE_EVAL?: unknown;
}

function isQueue(value: unknown): value is OnlineEvalQueue {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<OnlineEvalQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
}

/**
 * `env.ONLINE_EVAL`, when it really is a Queue producer binding.
 *
 * The SHAPE is checked rather than assumed, for the reason
 * `requestLogQueueFrom` gives: `env` is `unknown` here, and a plain var that
 * happened to carry this name would otherwise be `send()`-ed and fail after the
 * response was flushed, where nobody is watching.
 */
export function onlineEvalQueueFrom(env: unknown): OnlineEvalQueue | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as OnlineEvalSinkBindings).ONLINE_EVAL;
  return isQueue(candidate) ? candidate : undefined;
}

export interface OnlineEvalSinkOptions {
  readonly queue?: (env: unknown) => OnlineEvalQueue | undefined;
  readonly diagnostics?: { onError?(error: unknown): void } | undefined;
}

/** The producer. Built once at module scope; bindings arrive per request. */
export class OnlineEvalSink {
  #queued = 0;
  #dropped = 0;
  #failed = 0;
  readonly #skipped = new Map<string, number>();
  readonly #queueFor: (env: unknown) => OnlineEvalQueue | undefined;
  readonly #diagnostics: { onError?(error: unknown): void } | undefined;

  constructor(options: OnlineEvalSinkOptions = {}) {
    this.#queueFor = options.queue ?? onlineEvalQueueFrom;
    this.#diagnostics = options.diagnostics;
  }

  get stats(): OnlineEvalStats {
    return {
      queued: this.#queued,
      dropped: this.#dropped,
      failed: this.#failed,
      skipped: Object.fromEntries(this.#skipped),
    };
  }

  /** Count one request that was considered and not sampled. */
  skip(reason: string): void {
    this.#skipped.set(reason, (this.#skipped.get(reason) ?? 0) + 1);
  }

  /** NEVER REJECTS. See the module docs. */
  async enqueue(sample: OnlineEvalSample, runtime: { readonly env: unknown }): Promise<void> {
    const queue = this.#queueFor(runtime.env);
    if (queue === undefined) {
      this.#dropped += 1;
      return;
    }
    try {
      await queue.send(onlineEvalSampleToWire(sample));
      this.#queued += 1;
    } catch (error) {
      this.#failed += 1;
      this.#diagnostics?.onError?.(error);
    }
  }
}

/** Build the production sink. */
export function createOnlineEvalSink(options: OnlineEvalSinkOptions = {}): OnlineEvalSink {
  return new OnlineEvalSink(options);
}
