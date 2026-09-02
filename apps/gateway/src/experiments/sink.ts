/**
 * The shadow-arm observer — the seam between `inference/shadow.ts` and the
 * evidence tables.
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
 * With no `CONTROL_DB` (or `BILLING_DB`) binding there is nowhere for a leg to
 * go, so it is counted as `dropped` rather than silently discarded. "No shadow
 * rows" and "no database" must not look identical — that is #664's rule and it
 * is the difference between a broken deployment and one that simply is not
 * mirroring.
 */
import {
  type ExperimentDatabase,
  experimentDatabaseFrom,
  experimentTenantDatabaseFrom,
  writeShadowLeg,
  writeShadowLegProjection,
} from "./d1.js";
import type { ShadowLegRecord } from "./record.js";

/** What the observer has done since the isolate started. */
export interface ExperimentSinkStats {
  readonly written: number;
  /** Legs with nowhere to go — no control database bound. */
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
  readonly database?: (env: unknown) => ExperimentDatabase | undefined;
  readonly tenantDatabase?: (env: unknown, tenantId: string) => ExperimentDatabase | undefined;
  readonly projectionDatabase?: (env: unknown) => ExperimentDatabase | undefined;
  readonly diagnostics?: { onError?(error: unknown): void } | undefined;
  /**
   * Whether the object-authoritative write is ALSO mirrored to the control
   * projection. `false` in production — a shadow leg is tenant data and lives in
   * the owning object, never mirrored into the shared control store (#859/#881
   * red line, the same cut `assets/d1.ts`'s `projectToControl` made for audit
   * rows). The default stays `true` so the compat/repair seam and its existing
   * tests keep exercising the dual write; flipping the production flag back on is
   * the whole rollback.
   */
  readonly projectToControl?: boolean;
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
  readonly #databaseFor: (env: unknown) => ExperimentDatabase | undefined;
  readonly #tenantDatabaseFor: (env: unknown, tenantId: string) => ExperimentDatabase | undefined;
  readonly #projectionDatabaseFor: (env: unknown) => ExperimentDatabase | undefined;
  readonly #legacyDatabase: boolean;
  readonly #projectToControl: boolean;
  readonly #diagnostics: { onError?(error: unknown): void } | undefined;

  constructor(options: ExperimentSinkOptions = {}) {
    this.#databaseFor = options.database ?? experimentDatabaseFrom;
    this.#tenantDatabaseFor = options.tenantDatabase ?? experimentTenantDatabaseFrom;
    this.#projectionDatabaseFor = options.projectionDatabase ?? experimentDatabaseFrom;
    this.#legacyDatabase = options.database !== undefined;
    this.#projectToControl = options.projectToControl ?? true;
    this.#diagnostics = options.diagnostics;
  }

  get stats(): ExperimentSinkStats {
    return { written: this.#written, dropped: this.#dropped, failed: this.#failed };
  }

  /** NEVER REJECTS. See the module docs. */
  async observeShadowLeg(record: ShadowLegRecord, env: unknown): Promise<void> {
    try {
      if (this.#legacyDatabase) {
        const db = this.#databaseFor(env);
        if (db === undefined) {
          this.#dropped += 1;
          return;
        }
        // Explicit database injection is the compatibility seam. It still
        // targets CONTROL_D1, so it must use the tenant-qualified projection
        // key rather than the object's logical leg primary key.
        await writeShadowLegProjection(db, record);
      } else {
        const tenant = this.#tenantDatabaseFor(env, record.tenantId);
        // The control projection is resolved BEFORE any write only while it is
        // still a destination, so "nowhere to mirror" stays a `dropped` leg
        // rather than a half-written one. Production runs with
        // `projectToControl: false`: the object is the only destination, and an
        // absent projection binding is no longer a reason to drop the leg.
        const projection = this.#projectToControl ? this.#projectionDatabaseFor(env) : undefined;
        if (tenant === undefined || (this.#projectToControl && projection === undefined)) {
          this.#dropped += 1;
          return;
        }
        await writeShadowLeg(tenant, record);
        if (projection !== undefined) {
          await writeShadowLegProjection(projection, record);
        }
      }
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
const ISOLATE_EXPERIMENT_OBSERVER = new D1ExperimentObserver({ projectToControl: false });

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
