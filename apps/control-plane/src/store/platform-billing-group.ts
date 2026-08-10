/**
 * Platform billing groups with per-group price multipliers (#942, epic #941).
 *
 * A billing group binds a set of upstream providers
 * (`platform_provider_channels`) and carries ONE `multiplier`. A served
 * request's consumed price is the provider's official offering price times the
 * multiplier of the group its API key is bound to. Group ↔ provider is
 * many-to-many, so the same provider can bill at a different rate through two
 * groups.
 *
 * This is the sibling of {@link PlatformModelCatalogStore} and follows its two
 * structural rules exactly:
 *
 *  1. **The audit row is IN the mutation batch.** `#commit` batches the
 *     revision init, the mutation, the revision bump and the audit INSERT
 *     together (`runControlPlaneMutationWithAudit`'s shape), so a rejected
 *     audit append rolls the mutation back rather than leaving a committed
 *     change with an advanced revision and no evidence — the whole reason the
 *     platform stores do not use the tenant-side outbox.
 *  2. **No tenant on the record.** These are platform-scoped writes; the audit
 *     record carries no `tenant_id`, so they join the platform (null-tenant)
 *     audit chain where an operator looks for every other platform admin write.
 *
 * The `db` handle MUST be the CONTROL_DATA facade
 * (`control-data.ts::controlDatabaseFrom`), never a raw `env.DB` — the Zero-D1
 * seam #879 introduced, the same one {@link PlatformModelCatalogStore} takes.
 */
import type { CallerScope, StoreRecord } from "../ports.js";
import { type AuditAction, controlPlaneAuditJson, controlPlaneAuditStatement } from "./d1.js";
import { isMissingPlatformCatalogError } from "./platform-model-catalog.js";
import {
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
  TenantCatalogValidationError,
  boolSql,
  boolValue,
  hasOwn,
  isConstraintError,
} from "./tenant-model-catalog.js";

export const BILLING_GROUP_TABLE = "platform_billing_groups";
export const BILLING_GROUP_PROVIDER_TABLE = "platform_billing_group_providers";
export const BILLING_GROUP_REVISION_TABLE = "platform_billing_group_revisions";

/** Audit `collection` value — the platform billing-group registry. */
const GROUP_COLLECTION = "platform_billing_groups";

/** How many times `#commit` rebuilds its batch after a rolled-back attempt. */
const COMMIT_ATTEMPTS = 5;

const PLATFORM_SCOPE = "platform" as const;

/**
 * A constraint failure that names the audit chain, not the caller's payload.
 * Mirrors `platform-model-catalog.ts`: a persistent audit-chain-head collision
 * must not be reported to an operator as a 409 on THEIR data — it sends them to
 * look at their input instead of at the (transient) chain race.
 */
function isAuditAppendError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /audit_events/i.test(message);
}

/** A group create/replace payload as the admin surface hands it in. */
export interface BillingGroupInput {
  readonly id: string;
  readonly name: string;
  readonly multiplier: number;
  readonly description?: string | null;
  readonly enabled?: boolean;
}

/** A partial edit; only present keys are touched. */
export interface BillingGroupPatch {
  readonly name?: string;
  readonly multiplier?: number;
  readonly description?: string | null;
  readonly enabled?: boolean;
}

interface GroupRow {
  id: string;
  name: string;
  multiplier: number;
  description: string | null;
  enabled: number;
}

interface GroupProviderRow {
  group_id: string;
  provider_id: string;
}

/** The projected admin/read record for one group, with its bound provider ids. */
export interface BillingGroupRecord extends StoreRecord {
  readonly id: string;
  readonly scope: typeof PLATFORM_SCOPE;
  readonly name: string;
  readonly multiplier: number;
  readonly description: string | null;
  readonly enabled: boolean;
  readonly provider_ids: readonly string[];
}

/** A group's routing-relevant projection for the gateway multiplier source. */
export interface BillingGroupMultiplier {
  readonly id: string;
  readonly multiplier: number;
  readonly enabled: boolean;
}

const GROUP_SELECT = `SELECT id, name, multiplier, description, enabled FROM ${BILLING_GROUP_TABLE}`;

function groupRecord(row: GroupRow, providerIds: readonly string[]): BillingGroupRecord {
  return {
    id: row.id,
    scope: PLATFORM_SCOPE,
    name: row.name,
    multiplier: Number(row.multiplier),
    description: row.description,
    enabled: boolValue(row.enabled, true),
    provider_ids: providerIds,
  };
}

export interface PlatformBillingGroupStoreOptions {
  /** MUST be the CONTROL_DATA facade handle, not a raw `env.DB`. */
  readonly db: D1Database;
  readonly requestId?: string | null;
}

export class PlatformBillingGroupStore {
  readonly #db: D1Database;
  readonly #requestId: string;

  constructor(options: PlatformBillingGroupStoreOptions) {
    this.#db = options.db;
    this.#requestId = options.requestId ?? "";
  }

  // -- reads -----------------------------------------------------------------

  /** Every group with its bound provider ids, name order. Empty before 0028. */
  async listGroups(): Promise<readonly BillingGroupRecord[]> {
    try {
      const [groups, edges] = await Promise.all([
        this.#db.prepare(`${GROUP_SELECT} ORDER BY name ASC`).all<GroupRow>(),
        this.#db
          .prepare(`SELECT group_id, provider_id FROM ${BILLING_GROUP_PROVIDER_TABLE}`)
          .all<GroupProviderRow>(),
      ]);
      const byGroup = new Map<string, string[]>();
      for (const edge of edges.results) {
        const list = byGroup.get(edge.group_id) ?? [];
        list.push(edge.provider_id);
        byGroup.set(edge.group_id, list);
      }
      return groups.results.map((row) =>
        groupRecord(row, (byGroup.get(row.id) ?? []).sort()),
      );
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return [];
      throw error;
    }
  }

  /** One group with its provider ids, or `null` if it does not exist. */
  async getGroup(id: string): Promise<BillingGroupRecord | null> {
    try {
      const row = await this.#db.prepare(`${GROUP_SELECT} WHERE id = ?`).bind(id).first<GroupRow>();
      if (row === null) return null;
      const providers = await this.#db
        .prepare(
          `SELECT provider_id FROM ${BILLING_GROUP_PROVIDER_TABLE}
             WHERE group_id = ? ORDER BY provider_id ASC`,
        )
        .bind(id)
        .all<{ provider_id: string }>();
      return groupRecord(
        row,
        providers.results.map((p) => p.provider_id),
      );
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return null;
      throw error;
    }
  }

  /**
   * Multiplier snapshot for the gateway's cached source (#945).
   *
   * A missing registry (0028 not applied) is an EMPTY snapshot, never a throw:
   * the gateway reads that as "no group has a multiplier", i.e. everything bills
   * at 1.0 — the same fail-open direction a dangling `billing_group_id` takes.
   */
  async multiplierSnapshot(): Promise<readonly BillingGroupMultiplier[]> {
    try {
      const rows = await this.#db
        .prepare(`SELECT id, multiplier, enabled FROM ${BILLING_GROUP_TABLE}`)
        .all<GroupRow>();
      return rows.results.map((row) => ({
        id: row.id,
        multiplier: Number(row.multiplier),
        enabled: boolValue(row.enabled, true),
      }));
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return [];
      throw error;
    }
  }

  /** The current registry revision; `0` before the first mutation. */
  async revision(): Promise<number> {
    return this.#revision();
  }

  // -- writes ----------------------------------------------------------------

  async createGroup(scope: CallerScope, input: BillingGroupInput): Promise<BillingGroupRecord> {
    const normalized = this.#validate(input.name, input.multiplier);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      scope,
      "create",
      { id: input.id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${BILLING_GROUP_TABLE}
             (id, name, multiplier, description, enabled, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          normalized.name,
          normalized.multiplier,
          input.description ?? null,
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.getGroup(input.id);
    if (stored === null) throw new Error(`billing group ${input.id} disappeared after create`);
    return stored;
  }

  async updateGroup(
    scope: CallerScope,
    id: string,
    patch: BillingGroupPatch,
  ): Promise<BillingGroupRecord> {
    const existing = await this.getGroup(id);
    if (existing === null) throw new TenantCatalogNotFoundError(`billing group ${id} not found`);

    const fields: string[] = [];
    const values: (string | number | null)[] = [];
    if (hasOwn(patch, "name")) {
      const { name } = this.#validate(patch.name ?? "", existing.multiplier);
      fields.push("name = ?");
      values.push(name);
    }
    if (hasOwn(patch, "multiplier")) {
      const { multiplier } = this.#validate(existing.name, patch.multiplier ?? Number.NaN);
      fields.push("multiplier = ?");
      values.push(multiplier);
    }
    if (hasOwn(patch, "description")) {
      fields.push("description = ?");
      values.push(patch.description ?? null);
    }
    if (hasOwn(patch, "enabled")) {
      fields.push("enabled = ?");
      values.push(boolSql(patch.enabled));
    }
    if (fields.length === 0) return existing;

    const now = Math.floor(Date.now() / 1000);
    fields.push("updated_at_unix = ?");
    values.push(now);
    await this.#commit(
      scope,
      "replace",
      { id, scope: PLATFORM_SCOPE },
      // `OR IGNORE` so a rename onto a taken name is a clean 0-change no-op the
      // `requireMutation` guard turns into a single 409, not a constraint throw
      // retried five times against a deterministic failure (catalog parity).
      this.#db
        .prepare(`UPDATE OR IGNORE ${BILLING_GROUP_TABLE} SET ${fields.join(", ")} WHERE id = ?`)
        .bind(...values, id),
      true,
    );
    const stored = await this.getGroup(id);
    if (stored === null) throw new Error(`billing group ${id} disappeared after update`);
    return stored;
  }

  /** `false` if the group did not exist; its bindings CASCADE away with it. */
  async deleteGroup(scope: CallerScope, id: string): Promise<boolean> {
    return this.#commit(
      scope,
      "remove",
      { id, scope: PLATFORM_SCOPE },
      this.#db.prepare(`DELETE FROM ${BILLING_GROUP_TABLE} WHERE id = ?`).bind(id),
      false,
    );
  }

  /**
   * Bind a provider to a group. Idempotent: re-binding an existing edge is a
   * no-op that returns `false` (the route treats bind as idempotent either way).
   * Throws {@link TenantCatalogNotFoundError} if the group or the provider does
   * not exist.
   *
   * Both are pre-checked rather than left to the foreign key, because the edge
   * insert is `INSERT OR IGNORE`, and SQLite's OR IGNORE swallows a foreign-key
   * violation silently (0 rows) instead of raising it — so an unknown provider
   * would otherwise read back as an unremarkable no-op rather than a 404.
   */
  async bindProvider(
    scope: CallerScope,
    groupId: string,
    providerId: string,
  ): Promise<boolean> {
    if ((await this.getGroup(groupId)) === null) {
      throw new TenantCatalogNotFoundError(`billing group ${groupId} not found`);
    }
    if (!(await this.#providerExists(providerId))) {
      throw new TenantCatalogNotFoundError(`provider ${providerId} not found`);
    }
    const now = Math.floor(Date.now() / 1000);
    return this.#commit(
      scope,
      "merge",
      {
        id: `${groupId}:${providerId}`,
        scope: PLATFORM_SCOPE,
        group_id: groupId,
        provider_id: providerId,
      },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${BILLING_GROUP_PROVIDER_TABLE}
             (group_id, provider_id, created_at_unix) VALUES (?, ?, ?)`,
        )
        .bind(groupId, providerId, now),
      false,
    );
  }

  async #providerExists(providerId: string): Promise<boolean> {
    try {
      const row = await this.#db
        .prepare("SELECT 1 AS ok FROM platform_provider_channels WHERE id = ?")
        .bind(providerId)
        .first<{ ok: number }>();
      return row !== null;
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return false;
      throw error;
    }
  }

  /** `false` if the binding did not exist. */
  async unbindProvider(
    scope: CallerScope,
    groupId: string,
    providerId: string,
  ): Promise<boolean> {
    return this.#commit(
      scope,
      // `remove`, not `merge`: an auditor reading the platform chain must be
      // able to tell an unbind from the `merge` a bind writes on the same id.
      "remove",
      { id: `${groupId}:${providerId}`, scope: PLATFORM_SCOPE, group_id: groupId, provider_id: providerId },
      this.#db
        .prepare(
          `DELETE FROM ${BILLING_GROUP_PROVIDER_TABLE} WHERE group_id = ? AND provider_id = ?`,
        )
        .bind(groupId, providerId),
      false,
    );
  }

  // -- internals -------------------------------------------------------------

  #validate(name: string, multiplier: number): { name: string; multiplier: number } {
    const trimmed = (name ?? "").trim();
    if (trimmed.length === 0) {
      throw new TenantCatalogValidationError("billing group name is required");
    }
    if (!Number.isFinite(multiplier) || multiplier < 0) {
      throw new TenantCatalogValidationError("billing group multiplier must be a number >= 0");
    }
    return { name: trimmed, multiplier };
  }

  /**
   * Batch the revision init, the mutation, the revision bump and the audit
   * append together, exactly as {@link PlatformModelCatalogStore.#commit} does.
   * Returns `false` when the mutation changed nothing (e.g. deleting an absent
   * row): the revision does not advance and no audit is written for a no-op.
   */
  async #commit(
    scope: CallerScope,
    action: AuditAction,
    record: StoreRecord,
    mutation: D1PreparedStatement,
    requireMutation: boolean,
  ): Promise<boolean> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= COMMIT_ATTEMPTS; attempt += 1) {
      const now = Math.floor(Date.now() / 1000);
      const revision = (await this.#revision()) + 1;
      let results: readonly D1Result<unknown>[];
      try {
        results = await this.#db.batch([
          this.#db
            .prepare(
              `INSERT OR IGNORE INTO ${BILLING_GROUP_REVISION_TABLE} (id, revision, updated_at_unix)
               VALUES (1, 0, ?)`,
            )
            .bind(now),
          mutation,
          this.#db
            .prepare(
              `UPDATE ${BILLING_GROUP_REVISION_TABLE}
                  SET revision = revision + 1, updated_at_unix = ?
                WHERE id = 1 AND changes() > 0
                RETURNING revision`,
            )
            .bind(now),
          await controlPlaneAuditStatement(this.#db, {
            action,
            collection: GROUP_COLLECTION,
            record,
            revision,
            scope,
            requestId: this.#requestId,
            auditJson: controlPlaneAuditJson({
              action,
              collection: GROUP_COLLECTION,
              record,
              revision,
              scope,
            }),
          }),
        ]);
      } catch (error) {
        lastError = error;
        continue;
      }
      const mutationResult = results[1];
      if (requireMutation && Number(mutationResult?.meta.changes ?? 0) === 0) {
        throw new TenantCatalogConflictError("billing group constraint violated");
      }
      const bump = results[2];
      // The mutation changed nothing (idempotent no-op / absent row): the
      // `changes() > 0` guard skipped the bump, so nothing was audited either.
      if (bump === undefined || Number(bump.meta.changes ?? 0) === 0) return false;
      const bumped = Number(
        (bump.results[0] as { revision?: number | string } | undefined)?.revision ?? 0,
      );
      if (bumped !== revision) {
        throw new Error(`billing group revision bumped to ${bumped}, audited as ${revision}`);
      }
      if (Number(results[3]?.meta.changes ?? 0) === 0) {
        throw new Error("billing group audit row was not appended with the mutation");
      }
      return true;
    }
    if (isConstraintError(lastError) && !isAuditAppendError(lastError)) {
      throw new TenantCatalogConflictError("billing group constraint violated");
    }
    throw new Error(
      `billing group: ${action} ${String(record.id)} failed after ${COMMIT_ATTEMPTS} attempts`,
      { cause: lastError },
    );
  }

  async #revision(): Promise<number> {
    try {
      const row = await this.#db
        .prepare(`SELECT revision FROM ${BILLING_GROUP_REVISION_TABLE} WHERE id = 1`)
        .first<{ revision: number | string }>();
      return Number(row?.revision ?? 0);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return 0;
      throw error;
    }
  }
}
