import { controlDatabaseFrom } from "../control-data.js";
import type {
  BillingGroupRouting,
  InferenceBindings,
  PlatformBillingGroupSource,
} from "./ports.js";

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

/** Thirty seconds bounds staleness when an editor forgets to bump a revision. */
export const DEFAULT_BILLING_GROUP_CACHE_TTL_MS = 30_000;

const REVISION_SQL = "SELECT revision FROM platform_billing_group_revisions WHERE id = 1";

/** One graph read keeps each group and its provider edges in one snapshot. */
const GROUP_GRAPH_SQL = `
  SELECT g.id, g.multiplier, g.enabled, edge.provider_id
  FROM platform_billing_groups g
  LEFT JOIN platform_billing_group_providers edge ON edge.group_id = g.id
  ORDER BY g.id ASC, edge.provider_id ASC`;

interface BillingGroupRow {
  readonly id: string | null;
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
  readonly provider_id?: string | null;
}

/**
 * The routable multiplier map: group id → multiplier, holding ONLY enabled
 * groups whose multiplier parsed to a finite non-negative number. A disabled or
 * malformed group is simply absent, so a lookup on it falls to `1.0` — the same
 * fail-open reading a missing id gets.
 */
interface BillingGroupSnapshotEntry {
  readonly enabled: boolean;
  readonly multiplier: number | undefined;
  readonly providerIds: readonly string[];
}

type BillingGroupSnapshot = ReadonlyMap<string, BillingGroupSnapshotEntry>;

interface CacheEntry {
  readonly revision: number;
  readonly snapshot: BillingGroupSnapshot;
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

function snapshotFromRows(rows: readonly BillingGroupRow[]): BillingGroupSnapshot {
  const mutable = new Map<
    string,
    { enabled: boolean; multiplier: number | undefined; providerIds: Set<string> }
  >();
  for (const row of rows) {
    if (row.id === null) continue;
    const entry = mutable.get(row.id) ?? {
      enabled: rowIsEnabled(row.enabled),
      multiplier: parseMultiplier(row.multiplier),
      providerIds: new Set<string>(),
    };
    if (typeof row.provider_id === "string" && row.provider_id !== "") {
      entry.providerIds.add(row.provider_id);
    }
    mutable.set(row.id, entry);
  }
  const snapshot = new Map<string, BillingGroupSnapshotEntry>();
  for (const [id, entry] of mutable) {
    snapshot.set(id, { ...entry, providerIds: [...entry.providerIds] });
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
      const group = snapshot.get(groupId);
      return group?.enabled === true ? (group.multiplier ?? 1) : 1;
    } catch {
      // MONEY PATH: any unexpected failure (including a 503 posture throw from
      // `controlDatabaseFrom`) bills at the official price rather than failing
      // the served request. The blip is never cached, so the next request retries.
      return 1;
    }
  }

  async routingForGroup(
    env: InferenceBindings,
    groupId: string | undefined,
    _tenantId?: string | undefined,
  ): Promise<BillingGroupRouting | null> {
    if (groupId === undefined || groupId === "") return null;
    try {
      const group = (await this.#snapshot(env))?.get(groupId);
      return group?.enabled === true ? { providerIds: group.providerIds } : null;
    } catch {
      return null;
    }
  }

  /**
   * The current multiplier snapshot for `env`, or `undefined` when there is no
   * control database to read (a unit env, or a Worker the stanza has not
   * reached). Throws only when a genuine read fails, which the caller turns into
   * the fail-open `1.0`.
   */
  async #snapshot(env: InferenceBindings): Promise<BillingGroupSnapshot | undefined> {
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

    const result = await db.prepare(GROUP_GRAPH_SQL).all<BillingGroupRow>();
    const snapshot = snapshotFromRows(result.results);
    this.#byEnv.set(envKey, { revision, snapshot, expiresAt: now + this.#ttlMs });
    return snapshot;
  }
}

/**
 * The public KV snapshot of billing groups (#961) — the account-global config
 * that the control plane REPUBLISHES on every group mutation, replacing the old
 * per-tenant Durable Object fan-out. One object, atomically overwritten, read by
 * the money path in front of the control-database fallback.
 *
 * Only the money-path fields travel: `id`, `multiplier`, `enabled`, and the
 * routable `provider_ids`. `schema_version` gates the reader, and `revision`
 * lets a reader ignore a stale write that lost a KV race.
 */
export const PLATFORM_BILLING_GROUP_SNAPSHOT_KEY = "platform-config:billing-groups:v1";

export interface PlatformBillingGroupSnapshotRow {
  readonly id: string;
  readonly multiplier: number;
  readonly enabled: boolean;
  readonly provider_ids: readonly string[];
}

export interface PlatformBillingGroupSnapshot {
  readonly schema_version: 1;
  readonly revision: number;
  readonly published_at_unix: number;
  readonly groups: readonly PlatformBillingGroupSnapshotRow[];
}

/**
 * Parse and shape-check a raw KV value, returning `null` on any malformation so
 * the reader falls back to the control database rather than trusting garbage.
 * Individual `groups` rows are re-validated when the snapshot is indexed.
 */
export function parsePlatformBillingGroupSnapshot(
  raw: string,
): PlatformBillingGroupSnapshot | null {
  let parsed: Partial<PlatformBillingGroupSnapshot>;
  try {
    parsed = JSON.parse(raw) as Partial<PlatformBillingGroupSnapshot>;
  } catch {
    return null;
  }
  if (
    parsed.schema_version !== 1 ||
    typeof parsed.revision !== "number" ||
    !Number.isSafeInteger(parsed.revision) ||
    parsed.revision < 0 ||
    typeof parsed.published_at_unix !== "number" ||
    !Number.isSafeInteger(parsed.published_at_unix) ||
    parsed.published_at_unix < 0 ||
    !Array.isArray(parsed.groups)
  ) {
    return null;
  }
  return parsed as PlatformBillingGroupSnapshot;
}

/** Index a snapshot's rows into the same in-memory shape the control source builds. */
function snapshotFromKvRows(
  rows: readonly PlatformBillingGroupSnapshotRow[],
): BillingGroupSnapshot {
  const snapshot = new Map<string, BillingGroupSnapshotEntry>();
  for (const row of rows) {
    if (typeof row?.id !== "string" || row.id === "") continue;
    const providerIds = Array.isArray(row.provider_ids)
      ? [...new Set(row.provider_ids.filter((v): v is string => typeof v === "string" && v !== ""))]
      : [];
    snapshot.set(row.id, {
      enabled: row.enabled === true,
      multiplier: parseMultiplier(typeof row.multiplier === "number" ? row.multiplier : null),
      providerIds,
    });
  }
  return snapshot;
}

interface KvCacheEntry {
  readonly revision: number;
  readonly snapshot: BillingGroupSnapshot;
  readonly expiresAt: number;
}

/**
 * KV-FIRST billing-group multiplier source (#961) — a MONEY PATH read that
 * prefers the account-global `PLATFORM_CONFIG` snapshot the control plane
 * republishes on every mutation, over a cross-region read of the single-threaded
 * control object. This is the exact posture `platform-catalog.ts` uses for the
 * model catalog, applied to billing groups.
 *
 * ## KV-first, control-fallback (the chosen posture)
 *
 * The snapshot carries EVERY group — enabled and disabled alike — so a group id
 * PRESENT in it is authoritative: an enabled row answers its multiplier (a `0×`
 * comp included), a disabled or malformed row answers `1.0` (the official
 * price), byte-identical to the control source. A group id ABSENT from the
 * snapshot means it was created inside the reader's short cache window (the KV
 * object has not yet been re-read), so the read FALLS BACK to the control
 * database rather than mis-billing it as `1.0`. That fallback is the only
 * residual control-plane coupling on this path, and it fires only for the ~30s
 * cache window of a brand-new group.
 *
 * ## Fail OPEN on every axis (unchanged contract)
 *
 * No KV binding, an unreadable key, a malformed snapshot — none of these bill
 * anything but the fallback's answer, which itself fails open to `1.0`. A read
 * error is never cached; the stale-but-good snapshot (if any) is left intact and
 * the next request retries. The KV attempt is best-effort in front of the
 * control read, never a new way to fail a request.
 */
export class KvFirstBillingGroupSource implements PlatformBillingGroupSource {
  readonly #fallback: PlatformBillingGroupSource;
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #byEnv = new WeakMap<object, KvCacheEntry>();

  constructor(options: {
    fallback: PlatformBillingGroupSource;
    ttlMs?: number;
    now?: () => number;
  }) {
    this.#fallback = options.fallback;
    this.#ttlMs = options.ttlMs ?? DEFAULT_BILLING_GROUP_CACHE_TTL_MS;
    this.#now = options.now ?? Date.now;
  }

  async multiplierForGroup(
    env: InferenceBindings,
    groupId: string | undefined,
    tenantId?: string | undefined,
  ): Promise<number> {
    if (groupId === undefined || groupId === "") return 1;

    const snapshot = await this.#snapshot(env);
    if (snapshot !== undefined) {
      const group = snapshot.get(groupId);
      // A PRESENT id is authoritative; an ABSENT id may be freshly created, so
      // only then do we pay the control fallback (which itself fails open to 1.0).
      if (group !== undefined) return group.enabled ? (group.multiplier ?? 1) : 1;
    }

    return this.#fallback.multiplierForGroup(env, groupId, tenantId);
  }

  async routingForGroup(
    env: InferenceBindings,
    groupId: string | undefined,
    tenantId?: string | undefined,
  ): Promise<BillingGroupRouting | null> {
    if (groupId === undefined || groupId === "") return null;

    const snapshot = await this.#snapshot(env);
    if (snapshot !== undefined) {
      const group = snapshot.get(groupId);
      if (group !== undefined) return group.enabled ? { providerIds: group.providerIds } : null;
    }

    return (await this.#fallback.routingForGroup?.(env, groupId, tenantId)) ?? null;
  }

  /**
   * The cached KV snapshot for `env`, or `undefined` when KV is absent,
   * unreadable, or has no published object yet — each of which routes the caller
   * to the control fallback. A malformed value or a lost KV race serves the last
   * good snapshot rather than a regression; a read error is never cached.
   */
  async #snapshot(env: InferenceBindings): Promise<BillingGroupSnapshot | undefined> {
    const kv = env.PLATFORM_CONFIG as KVNamespace | undefined;
    if (kv === undefined) return undefined;

    const envKey = env as unknown as object;
    const cached = this.#byEnv.get(envKey);
    const now = this.#now();
    if (cached !== undefined && cached.expiresAt > now) return cached.snapshot;

    let raw: string | null;
    try {
      raw = await kv.get(PLATFORM_BILLING_GROUP_SNAPSHOT_KEY, { cacheTtl: 30 });
    } catch {
      // A KV blip is not a billing event: serve the last good snapshot if any,
      // otherwise defer to the control fallback. Never cache the failure.
      return cached?.snapshot;
    }
    if (raw === null) return undefined; // never published yet → control fallback

    const parsed = parsePlatformBillingGroupSnapshot(raw);
    if (parsed === null) return cached?.snapshot;
    if (cached !== undefined && parsed.revision < cached.revision) return cached.snapshot;

    const snapshot = snapshotFromKvRows(parsed.groups);
    this.#byEnv.set(envKey, { revision: parsed.revision, snapshot, expiresAt: now + this.#ttlMs });
    return snapshot;
  }
}

/**
 * Construct the control-database-only source; the returned object owns
 * isolate-local cache state. This is the KV-first source's fallback and the seam
 * the fleet-control matrix asserts still reads the authoritative control table.
 */
export function platformBillingGroupSourceFromControlData(
  options: { ttlMs?: number; now?: () => number } = {},
): PlatformBillingGroupSource {
  return new ControlDataPlatformBillingGroupSource(options);
}

/**
 * Construct the production source: KV-FIRST (#961) over the account-global
 * `PLATFORM_CONFIG` snapshot, with the control database as the fail-open
 * fallback for a group created inside the reader's cache window.
 */
export function platformBillingGroupSourceFromSharedConfig(
  options: { ttlMs?: number; now?: () => number } = {},
): PlatformBillingGroupSource {
  return new KvFirstBillingGroupSource({
    fallback: new ControlDataPlatformBillingGroupSource(options),
    ...options,
  });
}
