/**
 * Platform announcements (公告) — operator-authored notices shared to tenants
 * (#948, shared-config channel).
 *
 * The structural sibling of {@link PlatformBillingGroupStore}, trimmed: an
 * announcement is a single flat row (no provider junction, no multiplier), so
 * this store is just the guarded CRUD + monotone revision the shared-config
 * fan-out compares. It follows the same two rules the platform stores share:
 *
 *  1. **The audit row is IN the mutation batch.** `#commit` batches the revision
 *     init, the mutation, the revision bump and the audit INSERT together, so a
 *     rejected audit append rolls the mutation back rather than leaving a
 *     committed change with an advanced revision and no evidence.
 *  2. **No tenant on the record.** These are platform-scoped writes; the audit
 *     record carries no `tenant_id`, so they join the platform (null-tenant)
 *     audit chain.
 *
 * The `db` handle MUST be the CONTROL_DATA facade
 * (`control-data.ts::controlDatabaseFrom`), never a raw `env.DB`.
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

export const ANNOUNCEMENT_TABLE = "platform_announcements";
export const ANNOUNCEMENT_REVISION_TABLE = "platform_announcement_revisions";

/** Audit `collection` value — the platform announcement registry. */
const ANNOUNCEMENT_COLLECTION = "platform_announcements";

/** How many times `#commit` rebuilds its batch after a rolled-back attempt. */
const COMMIT_ATTEMPTS = 5;

const PLATFORM_SCOPE = "platform" as const;

/**
 * A constraint failure that names the audit chain, not the caller's payload —
 * mirrors {@link PlatformBillingGroupStore}: a persistent audit-chain-head
 * collision must not be reported to an operator as a 409 on THEIR data.
 */
function isAuditAppendError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /audit_events/i.test(message);
}

/** An announcement create/replace payload as the admin surface hands it in. */
export interface AnnouncementInput {
  readonly id: string;
  readonly title: string;
  readonly body: string;
  readonly level?: string;
  readonly enabled?: boolean;
  readonly startsAtUnix?: number | null;
  readonly endsAtUnix?: number | null;
}

/** A partial edit; only present keys are touched. */
export interface AnnouncementPatch {
  readonly title?: string;
  readonly body?: string;
  readonly level?: string;
  readonly enabled?: boolean;
  readonly startsAtUnix?: number | null;
  readonly endsAtUnix?: number | null;
}

interface AnnouncementRow {
  id: string;
  title: string;
  body: string;
  level: string;
  enabled: number;
  starts_at_unix: number | null;
  ends_at_unix: number | null;
}

/** The projected admin/read record for one announcement. */
export interface AnnouncementRecord extends StoreRecord {
  readonly id: string;
  readonly scope: typeof PLATFORM_SCOPE;
  readonly title: string;
  readonly body: string;
  readonly level: string;
  readonly enabled: boolean;
  readonly starts_at_unix: number | null;
  readonly ends_at_unix: number | null;
}

const ANNOUNCEMENT_SELECT = `SELECT id, title, body, level, enabled, starts_at_unix, ends_at_unix FROM ${ANNOUNCEMENT_TABLE}`;

function announcementRecord(row: AnnouncementRow): AnnouncementRecord {
  return {
    id: row.id,
    scope: PLATFORM_SCOPE,
    title: row.title,
    body: row.body,
    level: row.level,
    enabled: boolValue(row.enabled, true),
    starts_at_unix: row.starts_at_unix === null ? null : Number(row.starts_at_unix),
    ends_at_unix: row.ends_at_unix === null ? null : Number(row.ends_at_unix),
  };
}

export interface PlatformAnnouncementStoreOptions {
  /** MUST be the CONTROL_DATA facade handle, not a raw `env.DB`. */
  readonly db: D1Database;
  readonly requestId?: string | null;
}

export class PlatformAnnouncementStore {
  readonly #db: D1Database;
  readonly #requestId: string;

  constructor(options: PlatformAnnouncementStoreOptions) {
    this.#db = options.db;
    this.#requestId = options.requestId ?? "";
  }

  // -- reads -----------------------------------------------------------------

  /** Every announcement, id order. Empty before 0030 (missing table). */
  async listAnnouncements(): Promise<readonly AnnouncementRecord[]> {
    try {
      const rows = await this.#db
        .prepare(`${ANNOUNCEMENT_SELECT} ORDER BY id ASC`)
        .all<AnnouncementRow>();
      return rows.results.map(announcementRecord);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return [];
      throw error;
    }
  }

  /** One announcement, or `null` if it does not exist. */
  async getAnnouncement(id: string): Promise<AnnouncementRecord | null> {
    try {
      const row = await this.#db
        .prepare(`${ANNOUNCEMENT_SELECT} WHERE id = ?`)
        .bind(id)
        .first<AnnouncementRow>();
      return row === null ? null : announcementRecord(row);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return null;
      throw error;
    }
  }

  /** The current registry revision; `0` before the first mutation. */
  async revision(): Promise<number> {
    return this.#revision();
  }

  // -- writes ----------------------------------------------------------------

  async createAnnouncement(
    scope: CallerScope,
    input: AnnouncementInput,
  ): Promise<AnnouncementRecord> {
    const normalized = this.#validate(input.title, input.body, input.level);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      scope,
      "create",
      { id: input.id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${ANNOUNCEMENT_TABLE}
             (id, title, body, level, enabled, starts_at_unix, ends_at_unix, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          normalized.title,
          normalized.body,
          normalized.level,
          boolSql(input.enabled),
          input.startsAtUnix ?? null,
          input.endsAtUnix ?? null,
          now,
          now,
        ),
      true,
    );
    const stored = await this.getAnnouncement(input.id);
    if (stored === null) throw new Error(`announcement ${input.id} disappeared after create`);
    return stored;
  }

  async updateAnnouncement(
    scope: CallerScope,
    id: string,
    patch: AnnouncementPatch,
  ): Promise<AnnouncementRecord> {
    const existing = await this.getAnnouncement(id);
    if (existing === null) throw new TenantCatalogNotFoundError(`announcement ${id} not found`);

    const fields: string[] = [];
    const values: (string | number | null)[] = [];
    if (hasOwn(patch, "title")) {
      const { title } = this.#validate(patch.title ?? "", existing.body, existing.level);
      fields.push("title = ?");
      values.push(title);
    }
    if (hasOwn(patch, "body")) {
      const { body } = this.#validate(existing.title, patch.body ?? "", existing.level);
      fields.push("body = ?");
      values.push(body);
    }
    if (hasOwn(patch, "level")) {
      const { level } = this.#validate(existing.title, existing.body, patch.level);
      fields.push("level = ?");
      values.push(level);
    }
    if (hasOwn(patch, "enabled")) {
      fields.push("enabled = ?");
      values.push(boolSql(patch.enabled));
    }
    if (hasOwn(patch, "startsAtUnix")) {
      fields.push("starts_at_unix = ?");
      values.push(patch.startsAtUnix ?? null);
    }
    if (hasOwn(patch, "endsAtUnix")) {
      fields.push("ends_at_unix = ?");
      values.push(patch.endsAtUnix ?? null);
    }
    if (fields.length === 0) return existing;

    const now = Math.floor(Date.now() / 1000);
    fields.push("updated_at_unix = ?");
    values.push(now);
    await this.#commit(
      scope,
      "replace",
      { id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(`UPDATE ${ANNOUNCEMENT_TABLE} SET ${fields.join(", ")} WHERE id = ?`)
        .bind(...values, id),
      true,
    );
    const stored = await this.getAnnouncement(id);
    if (stored === null) throw new Error(`announcement ${id} disappeared after update`);
    return stored;
  }

  /** `false` if the announcement did not exist. */
  async deleteAnnouncement(scope: CallerScope, id: string): Promise<boolean> {
    return this.#commit(
      scope,
      "remove",
      { id, scope: PLATFORM_SCOPE },
      this.#db.prepare(`DELETE FROM ${ANNOUNCEMENT_TABLE} WHERE id = ?`).bind(id),
      false,
    );
  }

  // -- internals -------------------------------------------------------------

  #validate(
    title: string,
    body: string,
    level: string | undefined,
  ): { title: string; body: string; level: string } {
    const trimmedTitle = (title ?? "").trim();
    if (trimmedTitle.length === 0) {
      throw new TenantCatalogValidationError("announcement title is required");
    }
    const trimmedBody = (body ?? "").trim();
    if (trimmedBody.length === 0) {
      throw new TenantCatalogValidationError("announcement body is required");
    }
    const normalizedLevel = (level ?? "info").trim();
    return {
      title: trimmedTitle,
      body: trimmedBody,
      level: normalizedLevel.length === 0 ? "info" : normalizedLevel,
    };
  }

  /**
   * Batch the revision init, the mutation, the revision bump and the audit
   * append together, exactly as {@link PlatformBillingGroupStore.#commit} does.
   * Returns `false` when the mutation changed nothing.
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
              `INSERT OR IGNORE INTO ${ANNOUNCEMENT_REVISION_TABLE} (id, revision, updated_at_unix)
               VALUES (1, 0, ?)`,
            )
            .bind(now),
          mutation,
          this.#db
            .prepare(
              `UPDATE ${ANNOUNCEMENT_REVISION_TABLE}
                  SET revision = revision + 1, updated_at_unix = ?
                WHERE id = 1 AND changes() > 0
                RETURNING revision`,
            )
            .bind(now),
          await controlPlaneAuditStatement(this.#db, {
            action,
            collection: ANNOUNCEMENT_COLLECTION,
            record,
            revision,
            scope,
            requestId: this.#requestId,
            auditJson: controlPlaneAuditJson({
              action,
              collection: ANNOUNCEMENT_COLLECTION,
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
        throw new TenantCatalogConflictError("announcement constraint violated");
      }
      const bump = results[2];
      if (bump === undefined || Number(bump.meta.changes ?? 0) === 0) return false;
      const bumped = Number(
        (bump.results[0] as { revision?: number | string } | undefined)?.revision ?? 0,
      );
      if (bumped !== revision) {
        throw new Error(`announcement revision bumped to ${bumped}, audited as ${revision}`);
      }
      if (Number(results[3]?.meta.changes ?? 0) === 0) {
        throw new Error("announcement audit row was not appended with the mutation");
      }
      return true;
    }
    if (isConstraintError(lastError) && !isAuditAppendError(lastError)) {
      throw new TenantCatalogConflictError("announcement constraint violated");
    }
    throw new Error(
      `announcement: ${action} ${String(record.id)} failed after ${COMMIT_ATTEMPTS} attempts`,
      { cause: lastError },
    );
  }

  async #revision(): Promise<number> {
    try {
      const row = await this.#db
        .prepare(`SELECT revision FROM ${ANNOUNCEMENT_REVISION_TABLE} WHERE id = 1`)
        .first<{ revision: number | string }>();
      return Number(row?.revision ?? 0);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return 0;
      throw error;
    }
  }
}
