/**
 * Where a finished request log GOES, and the rule that governs every branch:
 * **a logging failure must never fail the request.**
 *
 * ## Two destinations, one writer
 *
 * ```
 *   requestLogging()                     [middleware.ts]
 *     └── ctx.waitUntil(sink.write(record, { env, ctx }))
 *            ├── env.REQUEST_LOG bound?  → Queue.send(wire)       ← preferred
 *            │      … later, on the consumer:
 *            │      queue(batch) → tenant object (attributed)
 *            │                   / PLATFORM_DATA object (un-attributed)
 *            └── else bindings bound?   → same object writes inline
 * ```
 *
 * The Queue is preferred because it is the shape that survives volume: a
 * hundred decisions arriving together become one object batch instead of a hundred
 * round trips, and a D1 that is briefly unavailable becomes a redelivery with
 * backoff instead of a lost row. The direct-D1 arm is not a stand-in for it —
 * it is the correct behaviour for `wrangler dev --local` and for a deployment
 * that has not provisioned a queue, and it uses the same object writers, so the
 * two arms cannot drift into storing different rows.
 *
 * Track A: there is no shared-CONTROL projection any more. An attributed row's
 * sole home is its tenant's own object; an un-attributed (platform-operator)
 * row's sole home is the PLATFORM_DATA singleton. The gateway no longer mirrors
 * either into the shared CONTROL object.
 *
 * With NO writer for a row (no tenant object for an attributed row, no
 * PLATFORM_DATA for an un-attributed one) the sink counts a `dropped`/`failed`
 * and returns. That is the degradation, and it is deliberately COUNTED rather
 * than silent: a gateway whose evidence is going nowhere must be able to say so
 * ({@link RequestLogSink.stats}, surfaced on the readiness/metrics surface),
 * because "no rows" and "no writer" look identical from the admin API — which
 * is the whole defect #664 exists to close.
 *
 * ## Why the hot path never awaits any of this
 *
 * `write` is only ever called from inside `ctx.waitUntil`, i.e. after the
 * response object exists and (for SSE) after the body has been consumed or
 * abandoned. Nothing here is in front of a client byte. Every rejection is
 * swallowed at this boundary and turned into a counter: an unavailable Queue,
 * a D1 error, a serialization failure, a `waitUntil` on an already-finalized
 * context. A gateway that returns 500 because its audit log was full has
 * turned a compliance feature into an outage.
 */

import { platformDatabaseFrom } from "../control-data.js";
import {
  type RequestLogDatabase,
  platformRequestLogStatements,
  requestLogTenantDatabaseFrom,
  writeTenantRequestLogs,
} from "./d1.js";
import type { RequestLogRecord } from "./record.js";
import { requestLogToWire } from "./record.js";

/**
 * `[[queues.producers]] binding = "REQUEST_LOG"`, structurally.
 *
 * A live `Queue` satisfies this with no cast, the same trick
 * `src/metering/ports.ts::MeteringQueue` plays, so the production code never
 * names a test double.
 */
export interface RequestLogQueue {
  send(body: unknown, options?: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>, options?: unknown): Promise<void>;
}

/** What the sink has done since the isolate started. */
export interface RequestLogStats {
  /** Records handed to the Queue producer. */
  readonly queued: number;
  /** Records written straight to the object path (no queue bound). */
  readonly written: number;
  /** Records with nowhere to go — no queue AND no destination object. */
  readonly dropped: number;
  /** Writes that were attempted and rejected. */
  readonly failed: number;
}

/** The bindings this slice reads, and nothing else. */
export interface RequestLogBindings {
  /** `[[queues.producers]] binding = "REQUEST_LOG"`. */
  readonly REQUEST_LOG?: unknown;
  /** `TENANT_DATA` — one authoritative request-log database per tenant. */
  readonly TENANT_DATA?: unknown;
}

/** The `ExecutionContext` slice this module needs. */
export interface RequestLogRuntime {
  readonly env: unknown;
  readonly ctx?: { waitUntil(work: Promise<unknown>): void } | undefined;
}

function isQueue(value: unknown): value is RequestLogQueue {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<RequestLogQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
}

function isDatabase(value: unknown): value is RequestLogDatabase {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<RequestLogDatabase>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

/**
 * `env.REQUEST_LOG`, when it really is a Queue producer binding.
 *
 * The SHAPE is checked rather than assumed because `env` is `unknown` here and
 * a plain var that happened to be called `REQUEST_LOG` would otherwise be
 * `send()`-ed — failing after the response was flushed, i.e. in the one place
 * nobody is watching.
 */
export function requestLogQueueFrom(env: unknown): RequestLogQueue | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as RequestLogBindings).REQUEST_LOG;
  return isQueue(candidate) ? candidate : undefined;
}

/** Resolve the authoritative object-backed database for one tenant. */
export function requestLogTenantDatabaseFromEnv(
  env: unknown,
  tenantId: string,
): RequestLogDatabase | undefined {
  return requestLogTenantDatabaseFrom(env, tenantId);
}

/**
 * `env.PLATFORM_DATA`, when it really is the platform-singleton facade
 * (Zero-D1 Plan B). The direct-D1 arm's home for unattributed rows, mirroring
 * what the queue consumer writes; `undefined` on a unit env or a Worker the
 * PLATFORM_DATA stanza has not yet reached, and the platform leg is then skipped
 * without touching the control projection write.
 */
export function requestLogPlatformDatabaseFrom(env: unknown): RequestLogDatabase | undefined {
  const candidate = platformDatabaseFrom(env);
  return isDatabase(candidate) ? candidate : undefined;
}

/** Told about every failure, so a degraded evidence path is observable. */
export interface RequestLogDiagnostics {
  onError?(stage: "queue" | "d1", error: unknown): void;
}

export interface RequestLogSinkOptions {
  readonly queue?: (env: unknown) => RequestLogQueue | undefined;
  readonly tenantDatabase?: (env: unknown, tenantId: string) => RequestLogDatabase | undefined;
  /** Zero-D1 Plan B: the PLATFORM_DATA singleton for unattributed rows. */
  readonly platformDatabase?: (env: unknown) => RequestLogDatabase | undefined;
  readonly diagnostics?: RequestLogDiagnostics | undefined;
}

/**
 * The production binding resolver: `env.REQUEST_LOG` + `env.CONTROL_DB`.
 *
 * Resolved PER REQUEST from the `env` the request carries, never captured at
 * construction. workerd refuses I/O started on behalf of a different request,
 * so a module-scoped "current env" slot is a correctness bug that only appears
 * under concurrency — the same reasoning `src/metering/runtime.ts` sets out at
 * length, and the same conclusion.
 */
export const requestLogBindingsFromEnv: Required<
  Pick<RequestLogSinkOptions, "queue" | "tenantDatabase" | "platformDatabase">
> = {
  queue: requestLogQueueFrom,
  tenantDatabase: requestLogTenantDatabaseFromEnv,
  platformDatabase: requestLogPlatformDatabaseFrom,
};

export class RequestLogSink {
  readonly #queueOf: (env: unknown) => RequestLogQueue | undefined;
  readonly #tenantDatabaseOf: (env: unknown, tenantId: string) => RequestLogDatabase | undefined;
  readonly #platformDatabaseOf: (env: unknown) => RequestLogDatabase | undefined;
  readonly #diagnostics: RequestLogDiagnostics | undefined;
  #queued = 0;
  #written = 0;
  #dropped = 0;
  #failed = 0;

  constructor(options: RequestLogSinkOptions = {}) {
    this.#queueOf = options.queue ?? requestLogQueueFrom;
    this.#tenantDatabaseOf = options.tenantDatabase ?? requestLogTenantDatabaseFromEnv;
    this.#platformDatabaseOf = options.platformDatabase ?? requestLogPlatformDatabaseFrom;
    this.#diagnostics = options.diagnostics;
  }

  get stats(): RequestLogStats {
    return {
      queued: this.#queued,
      written: this.#written,
      dropped: this.#dropped,
      failed: this.#failed,
    };
  }

  /**
   * Deliver one record. NEVER rejects.
   *
   * The promise it returns is what the caller hands to `ctx.waitUntil`, so it
   * resolves only once the write has actually landed (or failed) — returning
   * early would let the isolate be torn down mid-write, which is the failure
   * mode that produces a request the gateway served and has no record of.
   */
  async write(record: RequestLogRecord, runtime: RequestLogRuntime): Promise<void> {
    const queue = this.#queueOf(runtime.env);
    if (queue !== undefined) {
      try {
        await queue.send(requestLogToWire(record));
        this.#queued += 1;
        return;
      } catch (error) {
        // Fall through to D1 rather than losing the row: a queue outage should
        // degrade the batching, not the evidence.
        this.#failed += 1;
        this.#diagnostics?.onError?.("queue", error);
      }
    }

    try {
      if (record.tenantId !== undefined && record.tenantId !== "") {
        // Attributed rows: the tenant's own object is the sole, authoritative
        // home. Track A removed the shared-CONTROL projection mirror.
        const tenantDb = this.#tenantDatabaseOf(runtime.env, record.tenantId);
        if (tenantDb === undefined) {
          throw new Error(
            `authoritative TenantDataObject is unavailable for tenant ${record.tenantId}`,
          );
        }
        await writeTenantRequestLogs(tenantDb, [record]);
      } else {
        // Un-attributed (platform-operator) rows have no tenant object by
        // definition; the PLATFORM_DATA singleton is their sole, authoritative
        // home. A missing PLATFORM_DATA binding leaves the row nowhere to go —
        // counted as `dropped`, never silently lost.
        const platformDb = this.#platformDatabaseOf(runtime.env);
        if (platformDb === undefined) {
          this.#dropped += 1;
          return;
        }
        // Authoritative now (not a best-effort mirror): a failure propagates to
        // the catch below and is counted as `failed`, the same as a tenant write.
        await platformDb.batch(platformRequestLogStatements(platformDb, [record]));
      }
      this.#written += 1;
    } catch (error) {
      this.#failed += 1;
      this.#diagnostics?.onError?.("d1", error);
    }
  }
}

/** The composition root's constructor. */
export function createRequestLogSink(options: RequestLogSinkOptions = {}): RequestLogSink {
  return new RequestLogSink(options);
}
