/**
 * The shadow-arm observer — the seam between `inference/shadow.ts` and the
 * evidence table.
 *
 * ## Why the mirror gets a PORT and not an import
 *
 * `runShadowMirror` runs inside `ctx.waitUntil` on a request that has already
 * been served, and its whole design is that nothing it does can surface to the
 * client. Handing it a D1 binding directly would put a database call inside
 * five nested guarantees; handing it one narrow port keeps `shadow.ts`'s
 * dependency count at one and lets the suite that proves "a mirror never
 * affects the response" drive a recording double instead of a database.
 *
 * ## Every failure here is swallowed
 *
 * {@link ExperimentObserver.observeShadowLeg} NEVER REJECTS, the same contract
 * `evals/sink.ts` and `requestlog/sink.ts` hold, and for the same reason: it is
 * called from inside a fire-and-forget task, so a rejection could only surface
 * as a logged Worker exception on a request that succeeded. An observability
 * feature that makes a served request look failed is worse than one that
 * measures nothing.
 *
 * ## The unbound deployment measures nothing, and says so
 *
 * A shadow leg is tenant data: its only destination is the owning tenant's
 * object (#859/#881 red line — never mirrored into the shared control store,
 * whose projection was DROPPED by control migration 0043). With no reachable
 * tenant object there is nowhere for a leg to go, so it is counted as `dropped`
 * rather than silently discarded. "No shadow rows" and "no database" must not
 * look identical — that is #664's rule and it is the difference between a broken
 * deployment and one that simply is not mirroring.
 */
import {
  type ExperimentDatabase,
  experimentTenantDatabaseFrom,
  writeShadowLeg,
} from "./d1.js";
import type { ShadowLegRecord } from "./record.js";

/** What the observer has done since the isolate started. */
export interface ExperimentSinkStats {
  readonly written: number;
  /** Legs with nowhere to go — no tenant object reachable. */
  readonly dropped: number;
  /** Writes that were attempted and failed. */
  readonly failed: number;
}

/**
 * The port `inference/shadow.ts` depends on.
 *
 * ONE method and no runtime argument: the env is bound by
 * {@link experimentObserverFor} when `defaults.ts` resolves the deps for a
 * request, the same env-resolved shape `circuit` and `shadowBudget` use. A
 * `runtime.env` parameter here would have to be threaded through
 * `spawnShadowMirror` and `ShadowMirror`, i.e. through the one code path whose
 * whole design is that it carries as little as possible.
 */
export interface ExperimentObserver {
  observeShadowLeg(record: ShadowLegRecord): Promise<void>;
}

/**
 * The observer for a deployment that records nothing.
 *
 * Explicitly named rather than an inline `{}` so a `deps.experiments === null`
 * in a test reads as a decision. It is also the only correct default for a
 * caller that has no bindings at all.
 */
export const NO_EXPERIMENT_OBSERVER: ExperimentObserver = {
  async observeShadowLeg(): Promise<void> {
    // Nothing to record to. Deliberately not a counter: this instance is
    // chosen by a caller that asked for no recording, not by an absent binding.
  },
};

export interface ExperimentSinkOptions {
  readonly tenantDatabase?: (env: unknown, tenantId: string) => ExperimentDatabase | undefined;
  readonly diagnostics?: { onError?(error: unknown): void } | undefined;
}

/**
 * The production observer.
 *
 * Deliberately NOT an `implements ExperimentObserver`: its `observeShadowLeg`
 * takes the Worker `env` as a second argument, because the D1 binding only
 * exists per request while this object is isolate-scoped. The port is satisfied
 * by {@link experimentObserverFor}'s bound view, which is the only thing
 * `inference/shadow.ts` ever sees.
 */
export class D1ExperimentObserver {
  #written = 0;
  #dropped = 0;
  #failed = 0;
  readonly #tenantDatabaseFor: (env: unknown, tenantId: string) => ExperimentDatabase | undefined;
  readonly #diagnostics: { onError?(error: unknown): void } | undefined;

  constructor(options: ExperimentSinkOptions = {}) {
    this.#tenantDatabaseFor = options.tenantDatabase ?? experimentTenantDatabaseFrom;
    this.#diagnostics = options.diagnostics;
  }

  get stats(): ExperimentSinkStats {
    return { written: this.#written, dropped: this.#dropped, failed: this.#failed };
  }

  /** NEVER REJECTS. See the module docs. */
  async observeShadowLeg(record: ShadowLegRecord, env: unknown): Promise<void> {
    try {
      const tenant = this.#tenantDatabaseFor(env, record.tenantId);
      // The owning object is the sole destination; an unreachable object is a
      // `dropped` leg, never a half-written one.
      if (tenant === undefined) {
        this.#dropped += 1;
        return;
      }
      await writeShadowLeg(tenant, record);
      this.#written += 1;
    } catch (error) {
      this.#failed += 1;
      this.#diagnostics?.onError?.(error);
    }
  }
}

/** Build the production observer. */
export function createExperimentObserver(
  options: ExperimentSinkOptions = {},
): D1ExperimentObserver {
  return new D1ExperimentObserver(options);
}

/**
 * The ISOLATE-WIDE observer, not a per-request instance.
 *
 * Same choice `routingMetrics` makes and for the same reason: `stats` counts
 * across requests, and a fresh instance per request would count diligently and
 * report zero forever — a counter with no reader, which is the defect shape
 * this repository keeps finding.
 */
const ISOLATE_EXPERIMENT_OBSERVER = new D1ExperimentObserver();

/** Isolate-wide observer counters, for a diagnostics surface. */
export function experimentObserverStats(): ExperimentSinkStats {
  return ISOLATE_EXPERIMENT_OBSERVER.stats;
}

/**
 * The observer for a Worker `env` — the arm `defaults.ts` resolves.
 *
 * Returns a thin view that closes over `env` rather than a new observer, so the
 * counters stay isolate-wide while the D1 binding stays per request. There is
 * no "no binding" arm: an unbound deployment is counted as `dropped` by the
 * observer itself, because "no shadow rows" and "no database" must not look
 * identical.
 */
export function experimentObserverFor(env: unknown): ExperimentObserver {
  return {
    async observeShadowLeg(record: ShadowLegRecord): Promise<void> {
      await ISOLATE_EXPERIMENT_OBSERVER.observeShadowLeg(record, env);
    },
  };
}
