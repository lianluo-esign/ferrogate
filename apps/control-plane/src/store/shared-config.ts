/**
 * The control-plane WRITER of the shared-config async channel (#948).
 *
 * ## What this is
 *
 * Platform config — announcements (公告) today — is authored once, on the control
 * database, by an operator. Every tenant that needs it used to pay a synchronous
 * cross-region read of the single `ControlDataObject` to merge those shared rows
 * in at read time. This store is the other end of the fix: it renders that shared
 * config into a batch of parameterised statements and PUSHES it, one way, into
 * each tenant Durable Object's read-only mirror tables
 * (`0027_shared_config_mirror.sql`) through the privileged tenant-write RPC.
 * After the push a tenant resolves shared config from its own object with no
 * control-plane hop.
 *
 * Billing groups (分组) NO LONGER travel this channel: they moved to the
 * account-global `PLATFORM_CONFIG` KV snapshot (#961,
 * `platform-billing-group-cache.ts`), which the control plane republishes on
 * every mutation and the gateway reads KV-first — retiring the per-tenant
 * fan-out that made creating a group slow. The `shared_billing_groups` mirror
 * table remains as harmless dead schema.
 *
 * This module owns three things and deliberately nothing else:
 *   1. reading the current shared config + its monotone source revision;
 *   2. rendering it to guarded, idempotent {@link TenantDataStatement}s;
 *   3. the control-side push watermark (`shared_config_push_state`) that lets the
 *      cron pass skip the whole fleet fan-out when nothing has changed.
 * Addressing tenants and fanning out is the caller's job (seed-at-create and the
 * scheduled pass), so this store stays a pure renderer and is unit-testable
 * without a Durable Object.
 *
 * ## Guarded and idempotent
 *
 * The rendered statements are safe to apply any number of times and in any order
 * relative to a newer push: each row mutation is gated on the tenant's own
 * `shared_config_cursor` still being BEHIND the revision being applied, and the
 * cursor advances LAST, in the same transaction. Re-applying the current
 * revision is a no-op; applying a stale one is a no-op. That is what makes the
 * seed push, the cron push, and a lagging tenant's back-fill all converge to the
 * same state without coordination.
 */
import type { TenantDatabaseRouter, TenantObjectAddress } from "@ferrogate/storage";
import type { TenantDataStatement } from "@ferrogate/storage/durable-objects";
import type { ControlPlaneDeps } from "../ports.js";
import { PlatformAnnouncementStore } from "./platform-announcement.js";

/** The shared-config domains this channel carries. One cursor row per value. */
export const SHARED_CONFIG_DOMAINS = ["announcements"] as const;
export type SharedConfigDomain = (typeof SHARED_CONFIG_DOMAINS)[number];

/** A domain's rendered push: the revision it reflects and the statements to apply. */
export interface SharedConfigSnapshot {
  readonly domain: SharedConfigDomain;
  readonly revision: number;
  readonly statements: readonly TenantDataStatement[];
}

interface PushStateRow {
  readonly last_pushed_revision: number | null;
}

function nowUnix(now?: number): number {
  return now ?? Math.floor(Date.now() / 1000);
}

export interface SharedConfigStoreOptions {
  /** MUST be the CONTROL_DATA facade handle, not a raw `env.DB`. */
  readonly db: D1Database;
  readonly requestId?: string | null;
}

export class SharedConfigStore {
  readonly #db: D1Database;
  readonly #requestId: string;

  constructor(options: SharedConfigStoreOptions) {
    this.#db = options.db;
    this.#requestId = options.requestId ?? "";
  }

  // -- rendering -------------------------------------------------------------

  /**
   * Render the announcements (公告) mirror push at the current source revision.
   *
   * The statement list, in order: a behind-revision guard on every statement, a
   * full DELETE-then-reinsert so deletions land, and the cursor advancing LAST.
   * Every guard reads the cursor as it stood at the START of the transaction (the
   * cursor write is the final statement), so all steps agree on whether this push
   * applies. A missing cursor row reads as 0 (never synced), which back-fills an
   * existing tenant on its first push.
   */
  async announcementsSnapshot(now?: number): Promise<SharedConfigSnapshot> {
    const announcements = new PlatformAnnouncementStore({
      db: this.#db,
      requestId: this.#requestId,
    });
    const [records, revision] = await Promise.all([
      announcements.listAnnouncements(),
      announcements.revision(),
    ]);
    const at = nowUnix(now);
    const domain: SharedConfigDomain = "announcements";

    const behind =
      "COALESCE((SELECT revision FROM shared_config_cursor WHERE domain = 'announcements'), 0) < ?";

    const statements: TenantDataStatement[] = [
      { sql: `DELETE FROM shared_announcements WHERE ${behind}`, params: [revision] },
    ];
    for (const record of records) {
      statements.push({
        sql: `INSERT INTO shared_announcements (id, title, body, level, enabled, starts_at_unix, ends_at_unix, config_revision, synced_at_unix) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${behind}`,
        params: [
          record.id,
          record.title,
          record.body,
          record.level,
          record.enabled ? 1 : 0,
          record.starts_at_unix,
          record.ends_at_unix,
          revision,
          at,
          revision,
        ],
      });
    }
    statements.push({
      sql:
        "INSERT INTO shared_config_cursor (domain, revision, applied_at_unix) VALUES (?, ?, ?) " +
        "ON CONFLICT(domain) DO UPDATE SET revision = excluded.revision, " +
        "applied_at_unix = excluded.applied_at_unix WHERE excluded.revision > shared_config_cursor.revision",
      params: [domain, revision, at],
    });

    return { domain, revision, statements };
  }

  /** Render one domain's snapshot by name — the dispatcher seed/fan-out drive. */
  async snapshotForDomain(domain: SharedConfigDomain, now?: number): Promise<SharedConfigSnapshot> {
    switch (domain) {
      case "announcements":
        return this.announcementsSnapshot(now);
    }
  }

  // -- push watermark --------------------------------------------------------

  /** The revision the fleet was last fanned out at for `domain`; `0` if never. */
  async lastPushedRevision(domain: SharedConfigDomain): Promise<number> {
    const row = await this.#db
      .prepare("SELECT last_pushed_revision FROM shared_config_push_state WHERE domain = ?")
      .bind(domain)
      .first<PushStateRow>();
    return Number(row?.last_pushed_revision ?? 0);
  }

  /** Advance the fleet watermark after a fan-out. */
  async recordPush(
    domain: SharedConfigDomain,
    revision: number,
    tenantsPushed: number,
    now?: number,
  ): Promise<void> {
    await this.#db
      .prepare(
        "INSERT INTO shared_config_push_state " +
          "(domain, last_pushed_revision, tenants_pushed, updated_at_unix) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(domain) DO UPDATE SET last_pushed_revision = excluded.last_pushed_revision, " +
          "tenants_pushed = excluded.tenants_pushed, updated_at_unix = excluded.updated_at_unix",
      )
      .bind(domain, revision, tenantsPushed, nowUnix(now))
      .run();
  }
}

/**
 * Apply a shared-config push to ONE tenant's object through the privileged
 * tenant-write RPC. Mirrors the `rbac_registry` projection template: it refuses
 * loudly if the router cannot expose the privileged RPC (the memory/D1 backends
 * do not), which the seed caller swallows and the cron caller counts as a
 * failure. `address` is passed on the seed path — where the tenant's
 * jurisdiction/locationHint is in scope — so the FIRST push lands in the very
 * object the tenant will read from; the cron path resolves the object from the
 * id alone, matching how the fleet catalog-audit sweep already addresses it.
 */
export async function pushSharedConfigToTenant(
  router: TenantDatabaseRouter,
  tenantId: string,
  statements: readonly TenantDataStatement[],
  address?: TenantObjectAddress,
): Promise<void> {
  if (router.privilegedBatch === undefined) {
    throw new Error("shared-config push requires the privileged tenant object RPC");
  }
  await router.privilegedBatch(tenantId, statements, address);
}

/**
 * Seed a NEWLY created tenant with the full shared-config snapshot (#948).
 *
 * Called from `provisionTenantStorageFor` after the tenant's storage is
 * confirmed ready, so the tenant reads plans/groups locally from its first
 * request. Best-effort by contract: a failure here must not fail tenant
 * creation (the tenant is already committed), and the next cron pass — or the
 * next config edit — re-delivers idempotently. Returns `true` only when the
 * snapshot was actually pushed.
 */
export async function seedSharedConfigForTenant(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage">,
  tenantId: string,
  address?: TenantObjectAddress,
  now?: number,
): Promise<boolean> {
  if (deps.controlDatabase === null) return false;
  const router = deps.tenantStorage ?? deps.tenantDatabases;
  if (router.privilegedBatch === undefined) return false;
  try {
    const store = new SharedConfigStore({
      db: deps.controlDatabase,
      requestId: `seed-${tenantId}`,
    });
    // Every domain, concatenated into one privileged batch, so the first push a
    // tenant ever receives lands the whole shared-config surface atomically.
    const statements: TenantDataStatement[] = [];
    for (const domain of SHARED_CONFIG_DOMAINS) {
      const snapshot = await store.snapshotForDomain(domain, now);
      statements.push(...snapshot.statements);
    }
    await pushSharedConfigToTenant(router, tenantId, statements, address);
    return true;
  } catch (error) {
    console.warn(`control-plane: shared-config seed failed for ${tenantId}`, error);
    return false;
  }
}

/** One scheduled shared-config fan-out's outcome, folded into the tick report. */
export interface SharedConfigPassReport {
  readonly revision: number;
  readonly scanned: number;
  readonly pushed: number;
  readonly failed: number;
  readonly skipped: "control_database_unavailable" | "unchanged" | "roster_unavailable" | null;
}

/**
 * Push a just-committed platform config edit to the tenant fleet before the
 * operator write returns. A failed propagation must not turn a committed
 * create/update into an HTTP error that the console may retry as a duplicate;
 * the scheduled pass retains the unchanged watermark and retries it.
 */
export async function propagateSharedConfigAfterMutation(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage">,
  requestId: string,
): Promise<void> {
  try {
    const report = await fanOutSharedConfig(deps);
    if (report.failed > 0 || report.skipped === "roster_unavailable") {
      console.warn("control-plane: immediate shared-config propagation incomplete", {
        request_id: requestId,
        ...report,
      });
    }
  } catch (error) {
    console.warn("control-plane: immediate shared-config propagation failed", {
      request_id: requestId,
      error,
    });
  }
}

/**
 * Fan the current shared config out to every provisioned tenant — but only for
 * the domains whose source revision has moved past their fleet watermark, so an
 * unchanged fleet does zero tenant-object work. Each due domain's statements are
 * concatenated into ONE privileged batch per tenant, so a tenant that lags on
 * two domains still costs a single RPC. Each domain's watermark advances only on
 * a clean sweep (no per-tenant failure), so a transient failure re-attempts the
 * whole (idempotent) push next cadence rather than stranding a tenant behind.
 * Cadence gating is the caller's (the scheduled tick's) concern.
 */
export async function fanOutSharedConfig(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage">,
  now?: number,
): Promise<SharedConfigPassReport> {
  if (deps.controlDatabase === null) {
    return {
      revision: 0,
      scanned: 0,
      pushed: 0,
      failed: 0,
      skipped: "control_database_unavailable",
    };
  }
  const store = new SharedConfigStore({
    db: deps.controlDatabase,
    requestId: "cron-shared-config",
  });

  // Render every domain, keep only those the fleet watermark hasn't caught up to.
  const due: SharedConfigSnapshot[] = [];
  let maxRevision = 0;
  for (const domain of SHARED_CONFIG_DOMAINS) {
    const snapshot = await store.snapshotForDomain(domain, now);
    maxRevision = Math.max(maxRevision, snapshot.revision);
    if (snapshot.revision > (await store.lastPushedRevision(domain))) due.push(snapshot);
  }
  if (due.length === 0) {
    return { revision: maxRevision, scanned: 0, pushed: 0, failed: 0, skipped: "unchanged" };
  }

  const router = deps.tenantStorage ?? deps.tenantDatabases;
  let tenantIds: readonly string[];
  try {
    tenantIds = await router.provisionedTenants();
  } catch (error) {
    console.warn("control-plane: shared-config roster lookup failed", error);
    return {
      revision: maxRevision,
      scanned: 0,
      pushed: 0,
      failed: 1,
      skipped: "roster_unavailable",
    };
  }

  const statements = due.flatMap((snapshot) => snapshot.statements);
  let pushed = 0;
  let failed = 0;
  for (const tenantId of tenantIds) {
    try {
      await pushSharedConfigToTenant(router, tenantId, statements);
      pushed += 1;
    } catch (error) {
      failed += 1;
      console.warn(`control-plane: shared-config push failed for ${tenantId}`, error);
    }
  }
  // Only advance a domain's watermark on a clean sweep; a partial failure leaves
  // every due domain's watermark where it was so next cadence re-delivers all.
  if (failed === 0) {
    for (const snapshot of due) {
      await store.recordPush(snapshot.domain, snapshot.revision, pushed, now);
    }
  }
  return { revision: maxRevision, scanned: tenantIds.length, pushed, failed, skipped: null };
}
