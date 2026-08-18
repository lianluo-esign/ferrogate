import { controlDatabaseFrom } from "../control-data.js";
import {
  type TenancyBindings,
  type TenantDatabaseResolver,
  resolverForEnv,
} from "../tenancy/index.js";
import type { InferenceBindings, PlatformBillingGroupSource } from "./ports.js";

/**
 * The billing-group multiplier source for the inference data plane (#945, epic
 * #941 slice 4) — a MONEY PATH read.
 *
 * A tenant's API key may be bound to a `platform_billing_groups` row whose
 * `multiplier` scales the SETTLED price of every request that key serves. This
 * source is what makes that number readable by the settlement path: given the
 * key's `billing_group_id` (carried onto {@link Usage} via the caller), it
 * answers the multiplier an operator's CRUD write set, without a redeploy.
 *
 * ## Fail OPEN, on every axis, to the official price
 *
 * The multiplier is a *modifier* of a price that is already correct on its own.
 * So when the modifier cannot be resolved — no control database bound, the table
 * not yet migrated (or rolled back), the group absent, the group DISABLED, a
 * dangling id, or an outright read error — the answer is `1.0`, i.e. bill at the
 * official price. Refusing the request, or billing at `0`, would each turn a
 * lookup blip into a revenue event. The ONLY way `0` is billed is when an
 * ENABLED group explicitly sets `multiplier = 0` (a comp), which is a
 * deliberate operator decision, not a failure.
 *
 * ## Cache shape (mirrors `platform-catalog.ts`)
 *
 * A revision-gated, per-`env` {@link WeakMap} with a short TTL: one cheap
 * single-row revision read per request decides whether the cached snapshot is
 * still current, and the full table is only re-read when the revision moved or
 * the entry expired. A FAILURE is never cached — a cached blip would extend a
 * one-request failure into a TTL-long one — so the stale-but-good entry (if any)
 * is left intact and the next request retries.
 */

/** Five seconds bounds staleness when an editor forgets to bump a revision. */
export const DEFAULT_BILLING_GROUP_CACHE_TTL_MS = 5_000;

const REVISION_SQL = "SELECT revision FROM platform_billing_group_revisions WHERE id = 1";

/**
 * `id`, `multiplier` and `enabled` for every group — the exact projection
 * `PlatformBillingGroupStore.multiplierSnapshot()` returns. Inlined here rather
 * than imported from `apps/control-plane` to avoid a reverse dependency (the
 * store already imports FROM the gateway), byte-identical to that store's SQL.
 */
const MULTIPLIER_SQL = "SELECT id, multiplier, enabled FROM platform_billing_groups";

interface BillingGroupRow {
  readonly id: string | null;
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
}

/**
 * The routable multiplier map: group id → multiplier, holding ONLY enabled
 * groups whose multiplier parsed to a finite non-negative number. A disabled or
 * malformed group is simply absent, so a lookup on it falls to `1.0` — the same
 * fail-open reading a missing id gets.
 */
type MultiplierSnapshot = ReadonlyMap<string, number>;

interface CacheEntry {
  readonly revision: number;
  readonly snapshot: MultiplierSnapshot;
  readonly expiresAt: number;
}

/** A row is "enabled" only on a literal `1`, matching the store's boolean read. */
function rowIsEnabled(value: number | string | null): boolean {
  return value === 1 || value === "1";
}

/** Parse a `REAL CHECK (multiplier >= 0)` cell; reject NaN/Infinity/negatives. */
function parseMultiplier(value: number | string | null): number | undefined {
  if (value === null) return undefined;
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function snapshotFromRows(rows: readonly BillingGroupRow[]): MultiplierSnapshot {
  const snapshot = new Map<string, number>();
  for (const row of rows) {
    if (row.id === null || !rowIsEnabled(row.enabled)) continue;
    const multiplier = parseMultiplier(row.multiplier);
    if (multiplier === undefined) continue;
    snapshot.set(row.id, multiplier);
  }
  return snapshot;
}

/** Control-object-backed source with revision-aware, per-`env` caching. */
export class ControlDataPlatformBillingGroupSource implements PlatformBillingGroupSource {
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #byEnv = new WeakMap<object, CacheEntry>();

  constructor(options: { ttlMs?: number; now?: () => number } = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_BILLING_GROUP_CACHE_TTL_MS;
    this.#now = options.now ?? Date.now;
  }

  async multiplierForGroup(
    env: InferenceBindings,
    groupId: string | undefined,
    _tenantId?: string | undefined,
  ): Promise<number> {
    // The control source reads the account-global table directly; `tenantId` is
    // a hint only the mirror-first source in front of it consumes.
    if (groupId === undefined || groupId === "") return 1;
    try {
      const snapshot = await this.#snapshot(env);
      if (snapshot === undefined) return 1;
      return snapshot.get(groupId) ?? 1;
    } catch {
      // MONEY PATH: any unexpected failure (including a 503 posture throw from
      // `controlDatabaseFrom`) bills at the official price rather than failing
      // the served request. The blip is never cached, so the next request retries.
      return 1;
    }
  }

  /**
   * The current multiplier snapshot for `env`, or `undefined` when there is no
   * control database to read (a unit env, or a Worker the stanza has not
   * reached). Throws only when a genuine read fails, which the caller turns into
   * the fail-open `1.0`.
   */
  async #snapshot(env: InferenceBindings): Promise<MultiplierSnapshot | undefined> {
    const db = controlDatabaseFrom(env);
    if (db === undefined) return undefined;

    const envKey = env as unknown as object;
    const cached = this.#byEnv.get(envKey);

    const revisionRow = await db
      .prepare(REVISION_SQL)
      .first<{ revision: number | string | null }>();
    const revision =
      revisionRow === null || revisionRow.revision === null ? 0 : Number(revisionRow.revision);
    if (!Number.isSafeInteger(revision) || revision < 0) {
      // A garbage revision is not a green light to re-read; serve the last good
      // snapshot when there is one, otherwise fail open (no group is billed).
      return cached?.snapshot;
    }

    const now = this.#now();
    if (cached !== undefined && cached.revision === revision && cached.expiresAt > now) {
      return cached.snapshot;
    }

    const result = await db.prepare(MULTIPLIER_SQL).all<BillingGroupRow>();
    const snapshot = snapshotFromRows(result.results);
    this.#byEnv.set(envKey, { revision, snapshot, expiresAt: now + this.#ttlMs });
    return snapshot;
  }
}

/**
 * A single group's authoritative mirror row: `multiplier` and `enabled` exactly
 * as {@link ControlDataPlatformBillingGroupSource} reads them from the control
 * table, but from the tenant's own read-only `shared_billing_groups`.
 */
const MIRROR_GROUP_SQL = "SELECT multiplier, enabled FROM shared_billing_groups WHERE id = ?";

interface MirrorGroupRow {
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
}

/** Resolve `env`'s tenant-database resolver; the seam a unit test overrides. */
export type TenantResolverFor = (env: InferenceBindings) => TenantDatabaseResolver;

/**
 * Mirror-FIRST billing-group multiplier source (#960, Phase C step 7b) — a MONEY
 * PATH read that prefers the tenant's OWN read-only `shared_billing_groups`
 * mirror over a cross-region read of the single-threaded control object.
 *
 * ## Mirror-first, control-fallback (the chosen posture)
 *
 * The shared-config channel (#948) DELETE-then-reinserts EVERY group — enabled
 * and disabled alike — into each tenant object, so once a tenant has synced, a
 * group id PRESENT in its mirror is authoritative: an enabled row answers its
 * multiplier (a `0×` comp included), a disabled or malformed row answers `1.0`
 * (the official price), byte-identical to the control source. A group id ABSENT
 * from the mirror means the tenant has not synced that group yet — a group an
 * operator created and bound within a single push cadence — so the read FALLS
 * BACK to the control database rather than mis-billing it as `1.0`. That
 * fallback is the ONLY residual control-plane coupling on this path, and it
 * fires only for the sync window of a brand-new group.
 *
 * ## Fail OPEN on every axis (unchanged contract)
 *
 * No tenant id, no tenant router, the mirror table not migrated, the tenant
 * object unreachable, a read error — none of these bill anything but the
 * fallback's answer, which itself fails open to `1.0`. The tenant-mirror attempt
 * is best-effort in front of the control read, never a new way to fail a request.
 */
export class MirrorFirstBillingGroupSource implements PlatformBillingGroupSource {
  readonly #fallback: PlatformBillingGroupSource;
  readonly #resolverFor: TenantResolverFor;

  constructor(options: {
    fallback: PlatformBillingGroupSource;
    resolverFor?: TenantResolverFor;
  }) {
    this.#fallback = options.fallback;
    this.#resolverFor =
      options.resolverFor ?? ((env) => resolverForEnv(env as unknown as TenancyBindings));
  }

  async multiplierForGroup(
    env: InferenceBindings,
    groupId: string | undefined,
    tenantId?: string | undefined,
  ): Promise<number> {
    if (groupId === undefined || groupId === "") return 1;

    if (tenantId !== undefined && tenantId !== "") {
      const mirrored = await this.#fromMirror(env, groupId, tenantId);
      // `undefined` = the mirror could not answer authoritatively (not synced,
      // unreachable, or unmigrated); only then do we pay the control fallback.
      if (mirrored !== undefined) return mirrored;
    }

    return this.#fallback.multiplierForGroup(env, groupId, tenantId);
  }

  /**
   * The multiplier the tenant's mirror asserts for `groupId`, or `undefined`
   * when the mirror has no authoritative answer (row absent, or any read error).
   * A PRESENT row is authoritative: enabled → its parsed multiplier, otherwise
   * `1.0`.
   */
  async #fromMirror(
    env: InferenceBindings,
    groupId: string,
    tenantId: string,
  ): Promise<number | undefined> {
    try {
      const handle = await this.#resolverFor(env).forTenant(tenantId);
      const row = await handle.db.prepare(MIRROR_GROUP_SQL).bind(groupId).first<MirrorGroupRow>();
      if (row === null) return undefined; // not synced yet → let the fallback read it
      if (!rowIsEnabled(row.enabled)) return 1; // disabled → official price
      return parseMultiplier(row.multiplier) ?? 1; // malformed → official price
    } catch {
      // A missing mirror table or an unreachable tenant object is not a billing
      // event: defer to the control fallback (which itself fails open to 1.0).
      return undefined;
    }
  }
}

/**
 * Construct the production source; the returned object owns isolate-local cache
 * state. Mirror-FIRST (#960): a tenant reads its own `shared_billing_groups`
 * mirror and pays the control-plane read only for a group it has not synced yet.
 */
export function platformBillingGroupSourceFromControlData(
  options: { ttlMs?: number; now?: () => number; resolverFor?: TenantResolverFor } = {},
): PlatformBillingGroupSource {
  const fallback = new ControlDataPlatformBillingGroupSource(options);
  return new MirrorFirstBillingGroupSource({ fallback, resolverFor: options.resolverFor });
}
