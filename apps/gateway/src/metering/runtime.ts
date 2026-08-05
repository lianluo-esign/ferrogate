/**
 * The PER-REQUEST half of metering: turning a Worker's `env` into the durable
 * backend, and owning the `ctx.waitUntil` that keeps the write alive past the
 * flushed response.
 *
 * ## The problem this module exists to solve
 *
 * `UsageSink` is a construction-time dependency of the inference route module,
 * which is built ONCE at module scope (`src/index.ts`). Worker bindings and the
 * `ExecutionContext` are PER REQUEST. So the sink cannot hold `env.BILLING_DB`,
 * `env.BILLING` or `ctx` as construction state, and it may not read them from a
 * module-scoped "current request" slot either: workerd refuses I/O started on
 * behalf of a different request, so a last-write-wins slot is a correctness bug
 * that only appears under concurrency — the worst possible failure shape for a
 * billing path.
 *
 * The seam is therefore widened instead (`src/inference/ports.ts`:
 * `record(u, rc?)` where `rc` is `{ env, ctx }`), and everything derived from
 * `env` is memoized on the ENV OBJECT ITSELF via a `WeakMap`. That is the same
 * device `modelsFromEnv` already uses for the model registry: no ambient state,
 * no cross-request leakage, and the D1/Queue wrapper objects are still built
 * once per isolate rather than once per request.
 *
 * ## Structural bindings, no adapters
 *
 * `MeteringDatabase` and `MeteringQueue` (`./ports.ts`) are deliberately shaped
 * so a live `D1Database` / `Queue` satisfies them with no cast — the same trick
 * `src/assets/ports.ts` plays with `R2Bucket`. `test/metering/d1.test.ts` holds
 * that at COMPILE time (`_bindingsSatisfyThePorts`), and it plus
 * `test/metering/durable.test.ts` hold it at RUNTIME against the real
 * `BILLING_DB` / `BILLING` bindings vitest-pool-workers provisions from
 * `wrangler.toml`.
 */
import type { UsageRecordContext } from "../inference/ports.js";
import type { MeteringDatabase, MeteringQueue } from "./ports.js";
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
  /** `[[queues.producers]] binding = "BILLING"` — the billing report fan-out. */
  readonly BILLING?: MeteringQueue | undefined;
}

/** Structural check for a live `D1Database`. */
function isMeteringDatabase(value: unknown): value is MeteringDatabase {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<MeteringDatabase>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

/** Structural check for a live `Queue`. */
function isMeteringQueue(value: unknown): value is MeteringQueue {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<MeteringQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
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
  const candidate = (env as MeteringBindings).BILLING_DB;
  return isMeteringDatabase(candidate) ? candidate : undefined;
}

/** `env.BILLING`, when it is really a Queue producer binding. */
export function meteringQueueFrom(env: unknown): MeteringQueue | undefined {
  if (typeof env !== "object" || env === null) {
    return undefined;
  }
  const candidate = (env as MeteringBindings).BILLING;
  return isMeteringQueue(candidate) ? candidate : undefined;
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
  queue(env: unknown): MeteringQueue | undefined;
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
  /** `env.CONTROL_DB`/`env.BILLING_DB`, where derived usage snapshots project. */
  usageProjectionDatabase?(env: unknown): D1Database | undefined;
}

/** Resolve the control database used for tenant-derived fleet projections. */
export function meteringProjectionDatabaseFrom(env: unknown): D1Database | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const bindings = env as MeteringBindings;
  for (const candidate of [bindings.CONTROL_DB, bindings.BILLING_DB]) {
    if (isMeteringDatabase(candidate)) return candidate as unknown as D1Database;
  }
  return undefined;
}

/**
 * The production resolver: `TENANT_DATA`/`env.DB` + `env.BILLING_DB` fallback +
 * `env.BILLING`.
 *
 * `usageDatabase` is what mounts `@ferrogate/storage`'s `D1UsageLedger` on the
 * drain, which is the only thing that makes `usage_monthly_rollups` (the
 * monthly USD budget's input) and `usage_aggregate_rollups` (the monthly TOKEN
 * budget's input) non-empty. Both budget gates read tables that, before this,
 * nothing in `apps/` ever wrote.
 */
export const meteringBindingsFromEnv: MeteringBindingResolver = {
  database: meteringDatabaseFrom,
  queue: meteringQueueFrom,
  usageDatabase: usageDatabaseFrom,
  usageProjectionDatabase: meteringProjectionDatabaseFrom,
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
