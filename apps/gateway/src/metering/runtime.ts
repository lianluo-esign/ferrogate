import { platformDatabaseFrom } from "../control-data.js";
import type { UsageRecordContext } from "../inference/ports.js";
import type { MeteringDatabase } from "./ports.js";
import { usageDatabaseFrom } from "./usage-ledger.js";

/**
 * The bindings metering reads, and NOTHING else.
 *
 * Both are optional because the same code has to run in three places with
 * different amounts of Cloudflare underneath it: `wrangler dev --local` and the
 * deployed Worker (both), a unit test driving `app.request()` (neither), and
 * `vitest-pool-workers` (both, really provisioned). An absent binding degrades
 * to the in-isolate default rather than throwing — a metering failure must
 * never become a request failure — and the degradation is COUNTED and
 * observable, never silent (see `MeteringUsageSink.stats` /
 * `MeteringDiagnostics.onError`).
 */
export interface MeteringBindings {
  /**
   * `[[d1_databases]] binding = "BILLING_DB"` — the CONTROL compatibility
   * database. It retains legacy billing rows and receives derived projections;
   * tenant-scoped billing authority is resolved through `TENANT_DATA` below.
   *
   * `DB` is the legacy shared tenant-compatible binding. In the Durable Object
   * deployment, tenant-scoped calls use `TENANT_DATA` instead.
   */
  readonly BILLING_DB?: MeteringDatabase | undefined;
  /** `env.CONTROL_DB`, the fleet projection database for derived usage views. */
  readonly CONTROL_DB?: MeteringDatabase | undefined;
  /** `env.CONTROL_DATA`, the default singleton control database. */
  readonly CONTROL_DATA?: unknown;
  /** CONTROL storage posture; absent/empty defaults to CONTROL_DATA. */
  readonly GATEWAY_CONTROL_STORAGE?: string;
}

/** Structural check for a live `D1Database`. */
function isMeteringDatabase(value: unknown): value is MeteringDatabase {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<MeteringDatabase>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

/**
 * `env.BILLING_DB`, when it is really a D1 binding.
 *
 * The shape is checked rather than assumed because `env` is `unknown` at this
 * seam and a var named `BILLING_DB` (a string) would otherwise be handed to
 * `D1LedgerStore`, which would fail on the first `prepare` — after the response
 * had already been served, i.e. in the one place nobody is watching.
 */
export function meteringDatabaseFrom(
  env: unknown,
  tenantId?: string,
): MeteringDatabase | undefined {
  if (tenantId !== undefined) {
    const candidate = usageDatabaseFrom(env, tenantId);
    return isMeteringDatabase(candidate) ? candidate : undefined;
  }
  if (typeof env !== "object" || env === null) {
    return undefined;
  }
  // Track A hard-cut: unattributed (`tenant IS NULL`) settlement now lands in the
  // PLATFORM_DATA singleton — its authoritative home — never the shared control
  // projection. A single store and a single outbox preserve the single-drain-source
  // invariant the sweep depends on.
  const candidate = platformDatabaseFrom(env);
  return isMeteringDatabase(candidate) ? candidate : undefined;
}

/**
 * How the sink resolves its durable backend from a request's bindings.
 *
 * Supplying this is what switches `MeteringUsageSink` out of "drain myself into
 * the in-isolate ledger" mode and into "someone who holds the request context
 * drains me" mode — see `MeteringSinkOptions.bindings`.
 */
export interface MeteringBindingResolver {
  /** Resolve tenant authority when `tenantId` is supplied, or control compatibility otherwise. */
  database(env: unknown, tenantId?: string): MeteringDatabase | undefined;
  /**
   * `env.DB`/`TENANT_DATA` — the tenant database the committed-token /
   * monthly-spend aggregates accumulate into (`./usage-ledger.ts`).
   *
   * A separate seam, not a rename of `database()`: billing settlement and usage
   * aggregation are distinct batches even inside one tenant object. Optional so
   * a resolver that only knows about the billing half (a test double) still
   * satisfies the interface and simply accumulates nothing.
   */
  usageDatabase?(env: unknown, tenantId?: string): D1Database | undefined;
}

/**
 * The production resolver uses only the authoritative DO storage.
 * No environment binding can re-enable billing report fan-out.
 *
 * `usageDatabase` is what mounts `@ferrogate/storage`'s `D1UsageLedger` on the
 * drain, which is the only thing that makes `usage_monthly_rollups` (the
 * monthly USD budget's input) and `usage_aggregate_rollups` (the monthly TOKEN
 * budget's input) non-empty. Both budget gates read tables that, before this,
 * nothing in `apps/` ever wrote.
 */
export const meteringBindingsFromEnv: MeteringBindingResolver = {
  database: meteringDatabaseFrom,
  usageDatabase: usageDatabaseFrom,
};

/**
 * `c.executionCtx` without the throw.
 *
 * Hono's accessor RAISES when the context was built without one, which is what
 * `app.request(...)` does in a unit test. Metering treats an absent context as
 * "no `waitUntil` available", never as an error.
 */
export function executionContextOf(candidate: {
  executionCtx: UsageRecordContext["ctx"];
}): UsageRecordContext["ctx"] {
  try {
    return candidate.executionCtx;
  } catch {
    return undefined;
  }
}
