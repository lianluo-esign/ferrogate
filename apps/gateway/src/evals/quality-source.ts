/**
 * The ROUTER-CONSUMABLE half of #894: one tenant's per-leg quality verdicts,
 * behind the same peek/warm memo `./source.ts` uses for the policy.
 *
 * ============================================================================
 * WHY THIS IS A MEMO AND NOT A READ
 * ============================================================================
 *
 * Candidate ordering is `inference/strategy.ts::orderCandidatesByStrategy`,
 * which is pure and SYNCHRONOUS, and `handlers.ts::planUpstream` — its only
 * caller — returns a `PlannedRequest`, not a `Promise`, at seven call sites.
 * Making either async to fetch a quality number would put a D1 round trip in
 * front of every client's first upstream byte in order to steer a fraction of
 * requests. That is the trade `./source.ts` already refused for the sampling
 * decision, and it is refused here for the same reason and with the same
 * device: {@link OnlineEvalLegQualitySource.peek} answers ONLY from the isolate
 * memo and never does I/O, and the deferred half of `./middleware.ts` warms it
 * after the response has been served.
 *
 * The stated consequence, exactly as for the policy: **the first requests an
 * isolate serves for a tenant see no quality signal at all.** They are ordered
 * by the configured strategy alone, which is the behaviour of every deployment
 * before this slice. Under-steering is the safe error; blocking is not.
 *
 * ## `ok: false` is never cached
 *
 * `cachedOnlineEvalLegQualitySource` writes an entry only inside `if
 * (resolved.ok)`, same as `cachedOnlineEvalPolicySource`. A one-request D1 blip
 * must not become a TTL-long hole in the signal — and, worse here than there, a
 * cached failure would read as `no_signal`, i.e. as "this leg is fine".
 *
 * ## The fail direction is NO SIGNAL
 *
 * Every failure arm resolves to a snapshot that answers `no_signal` for every
 * leg. A quality signal that cannot be read must never be able to reorder a
 * ladder, and must never be able to refuse a request: this is a measurement, and
 * `./policy.ts` is explicit that an observability control may not take the data
 * plane down.
 */
import type { PhysicalRoute } from "../inference/ports.js";
import { NO_ROUTING_QUALITY } from "../inference/strategy.js";
import type { RoutingQuality, RoutingQualityPort } from "../inference/strategy.js";
import { type OnlineEvalScoreDatabase, onlineEvalDatabaseFrom } from "./d1.js";
import {
  type LegQualityVerdict,
  NO_LEG_QUALITY_SIGNAL,
  type OnlineEvalLegAggregate,
  legQualityKey,
  legQualityVerdicts,
  readOnlineEvalLegQuality,
} from "./leg-quality.js";
import {
  type OnlineEvalBindings,
  type OnlineEvalPolicySource,
  onlineEvalPolicySourceFromEnv,
} from "./source.js";

/** One tenant's verdicts, frozen at the moment the memo was warmed. */
export interface TenantLegQuality {
  /** SYNCHRONOUS and total. `no_signal` for anything not measured. */
  verdictFor(logicalModel: string, provider: string, providerModel: string): LegQualityVerdict;
}

/** The snapshot every failure arm resolves to. */
export const NO_LEG_QUALITY: TenantLegQuality = {
  verdictFor(): LegQualityVerdict {
    return NO_LEG_QUALITY_SIGNAL;
  },
};

export function tenantLegQualityFrom(verdicts: Map<string, LegQualityVerdict>): TenantLegQuality {
  return {
    verdictFor(logicalModel, provider, providerModel): LegQualityVerdict {
      return (
        verdicts.get(legQualityKey(logicalModel, provider, providerModel)) ?? NO_LEG_QUALITY_SIGNAL
      );
    },
  };
}

/**
 * `quality` is always a complete answer; `ok: false` says the read or the
 * tenant's thresholds could not be obtained, which is counted separately from
 * "measured nothing" for the same reason `./source.ts` separates them.
 */
export type LegQualityResolution =
  | { readonly ok: true; readonly quality: TenantLegQuality }
  | { readonly ok: false; readonly detail: string };

export interface OnlineEvalLegQualitySource {
  qualityFor(tenantId: string): Promise<LegQualityResolution>;
  /** The memoized answer, or `undefined`. NEVER does I/O. */
  peek(tenantId: string): LegQualityResolution | undefined;
}

/** A source that signals nothing — the unconfigured deployment. */
export const NO_ONLINE_EVAL_LEG_QUALITY: OnlineEvalLegQualitySource = {
  async qualityFor(): Promise<LegQualityResolution> {
    return { ok: true, quality: NO_LEG_QUALITY };
  },
  peek(): LegQualityResolution {
    return { ok: true, quality: NO_LEG_QUALITY };
  },
};

/**
 * The durable source: one seek for the tenant's projected cells, compared under
 * that tenant's OWN `regressionDrop` / `regressionMinSamples`.
 *
 * The thresholds are read from the policy source rather than defaulted, exactly
 * as `regression.ts` refuses to sweep a tenant under a fleet default: those two
 * numbers are the tenant's statement of what difference they consider real, and
 * applying somebody else's would demote a leg on evidence its owner never
 * accepted. A tenant with no policy row has not opted in, has no scores, and
 * resolves to {@link NO_LEG_QUALITY} — an `ok: true` complete answer.
 */
export function d1OnlineEvalLegQualitySource(
  db: OnlineEvalScoreDatabase,
  policies: OnlineEvalPolicySource,
): OnlineEvalLegQualitySource {
  return {
    async qualityFor(tenantId: string): Promise<LegQualityResolution> {
      const resolved = await policies.policyFor(tenantId).catch(() => undefined);
      if (resolved === undefined) return { ok: false, detail: "policy source threw" };
      if (!resolved.ok) return { ok: false, detail: resolved.detail };
      const policy = resolved.policy;
      if (policy === null) return { ok: true, quality: NO_LEG_QUALITY };

      let aggregates: OnlineEvalLegAggregate[];
      try {
        aggregates = await readOnlineEvalLegQuality(db, tenantId);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        // A schema that predates `0026_online_eval_leg_quality.sql` holds no
        // aggregate at all, which is a COMPLETE answer ("nothing measured")
        // rather than a failure to read one — and, unlike a blip, retrying it
        // every 30 seconds would never produce a different result.
        if (/no such table:\s*online_eval_leg_quality/i.test(detail)) {
          return { ok: true, quality: NO_LEG_QUALITY };
        }
        return { ok: false, detail };
      }
      return { ok: true, quality: tenantLegQualityFrom(legQualityVerdicts(aggregates, policy)) };
    },
    peek(): undefined {
      // D1 has no synchronous read; the memo below is what makes `peek` answer.
      return undefined;
    },
  };
}

/**
 * How long a resolved snapshot is trusted inside one isolate.
 *
 * Longer than the policy's 30s and deliberately so: the policy TTL is short
 * because an operator switches SAMPLING off in a hurry and warm isolates must
 * stop copying prompts quickly. Nothing about this snapshot copies anything —
 * it is a read-only reordering hint over a SEVEN-DAY window that the queue
 * consumer moves by fractions of a percent per batch, so re-reading it every 30
 * seconds would be a D1 seek per tenant per 30s to observe a number that cannot
 * have moved.
 */
export const DEFAULT_LEG_QUALITY_TTL_MS = 120_000;

/** Per-isolate, per-TENANT memo. An `ok: false` is NEVER cached. */
export function cachedOnlineEvalLegQualitySource(
  inner: OnlineEvalLegQualitySource,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): OnlineEvalLegQualitySource {
  const ttlMs = options.ttlMs ?? DEFAULT_LEG_QUALITY_TTL_MS;
  const now = options.now ?? ((): number => Date.now());
  const entries = new Map<string, { quality: TenantLegQuality; expiresAtMs: number }>();

  return {
    async qualityFor(tenantId: string): Promise<LegQualityResolution> {
      const hit = entries.get(tenantId);
      if (hit !== undefined && hit.expiresAtMs > now()) return { ok: true, quality: hit.quality };
      const resolved = await inner.qualityFor(tenantId);
      if (resolved.ok) {
        entries.set(tenantId, { quality: resolved.quality, expiresAtMs: now() + ttlMs });
      }
      return resolved;
    },
    peek(tenantId: string): LegQualityResolution | undefined {
      const hit = entries.get(tenantId);
      if (hit !== undefined && hit.expiresAtMs > now()) return { ok: true, quality: hit.quality };
      return inner.peek(tenantId);
    },
  };
}

/**
 * Memoized PER ENV OBJECT, the device `./source.ts`, `residency/source.ts` and
 * `attribution/source.ts` all use: Workers hands the same `env` to every request
 * an isolate serves, so this is an isolate-lifetime cache with no module global
 * a test cannot reset.
 */
const SOURCES = new WeakMap<object, OnlineEvalLegQualitySource>();

export function onlineEvalLegQualitySourceFromEnv(
  env: OnlineEvalBindings,
): OnlineEvalLegQualitySource {
  const key = env as unknown as object;
  const memoized = SOURCES.get(key);
  if (memoized !== undefined) return memoized;
  const db = onlineEvalDatabaseFrom(env);
  const source =
    db === undefined
      ? NO_ONLINE_EVAL_LEG_QUALITY
      : cachedOnlineEvalLegQualitySource(
          d1OnlineEvalLegQualitySource(db, onlineEvalPolicySourceFromEnv(env)),
        );
  SOURCES.set(key, source);
  return source;
}

/**
 * The synchronous port the inference router holds.
 *
 * `ladderQuality` reads `peek` and NOTHING else — no await, no promise, no
 * floating read started on the request path. `undefined` when the memo is cold,
 * which `orderCandidatesByStrategy` treats as "no quality input", i.e. as the
 * pre-#894 ordering.
 */
export function routingQualityPortFrom(source: OnlineEvalLegQualitySource): RoutingQualityPort {
  return {
    ladderQuality(tenantId: string, logicalModel: string): RoutingQuality | undefined {
      const peeked = source.peek(tenantId);
      if (peeked === undefined || !peeked.ok) return undefined;
      const quality = peeked.quality;
      return {
        lags(route: PhysicalRoute): boolean {
          return (
            quality.verdictFor(logicalModel, route.provider, route.providerModel).kind === "lagging"
          );
        },
      };
    },
  };
}

/**
 * `defaults.ts`'s env-resolved default.
 *
 * A deployment with no evaluation storage gets {@link NO_ROUTING_QUALITY} by
 * IDENTITY rather than a port wrapped around {@link NO_ONLINE_EVAL_LEG_QUALITY}.
 * The two are behaviourally identical for the router (both leave every ladder in
 * the strategy's order), and the point of naming the unconfigured case is that
 * `deps.routingQuality === NO_ROUTING_QUALITY` is a thing a test can assert —
 * which is not true of an anonymous closure over an empty snapshot.
 */
export function routingQualityPortFor(env: OnlineEvalBindings): RoutingQualityPort {
  const source = onlineEvalLegQualitySourceFromEnv(env);
  if (source === NO_ONLINE_EVAL_LEG_QUALITY) return NO_ROUTING_QUALITY;
  return routingQualityPortFrom(source);
}

/** Warm one tenant's snapshot. Called from the DEFERRED half of the sampler. */
export async function warmLegQuality(env: OnlineEvalBindings, tenantId: string): Promise<void> {
  await onlineEvalLegQualitySourceFromEnv(env)
    .qualityFor(tenantId)
    .catch(() => undefined);
}
