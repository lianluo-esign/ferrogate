/**
 * `D1SiteDomainVerificationStore` — the durable half of `../site-domain.ts`
 * (issues #488/#576), on the CONTROL database.
 *
 * ## The one thing this class exists for
 *
 * `try_begin_site_domain_verification_attempt` is a RATE LIMIT on outbound DNS,
 * and a rate limit implemented as read-decide-write is not a rate limit. The
 * pure {@link ../site-domain.js siteDomainVerificationAttemptDecision} was
 * already ported, and the only caller read the row, asked it, and then wrote
 * `last_checked_at_unix` unconditionally — so two concurrent
 * `POST /admin/v1/site-domains/{hostname}/verify` calls both read the same
 * `lastCheckedAtUnix`, were both told `allowed`, and both reached the DNS
 * lookup. #576 exists precisely so that an `admin.write` credential cannot
 * drive unbounded outbound DNS, and a window that a caller can widen by
 * concurrency defeats it.
 *
 * Rust never asks the pure function to DECIDE either. It puts the cooldown
 * predicate INSIDE the writing statement
 * (`control_plane_store_d1/rbac_site_domain.rs`):
 *
 * ```sql
 * UPDATE site_domain_verifications
 *    SET last_checked_at_unix = ?, updated_at_unix = ?
 *  WHERE tenant_id = ? AND hostname = ?
 *    AND (last_checked_at_unix IS NULL OR ? - last_checked_at_unix >= ?)
 * ```
 *
 * `changes() > 0` **is** the grant: the slot was reserved by the same statement
 * that decided it was free, inside SQLite's implicit transaction, so exactly one
 * of two racing callers can win. The pure decision function then runs only to
 * LABEL a refusal with a `retryAfterSecs` — it never authorizes anything.
 *
 * ## Which database, and why the row must be typed
 *
 * `site_domain_verifications` is a CONTROL-database table
 * (`sql/d1-ts/control/0001_init_control.sql`), keyed `(tenant_id, hostname)` so
 * a challenge one tenant started can never be redeemed by another. This store
 * therefore takes the control `D1Database` directly rather than a
 * `TenantDatabaseHandle` — there is no per-tenant routing to do, and routing it
 * per tenant would break the cross-tenant hostname-claim check.
 *
 * The typed table is also what makes the guard expressible at all: the generic
 * `control_plane_resources` document store keeps the record as an opaque JSON
 * blob, and a cooldown predicate over `json_extract(...)` cannot use the
 * `(tenant_id, hostname)` primary key, so the guarded UPDATE would degrade to a
 * scan. Ported onto the typed table for that reason.
 *
 * ## No `batch()`
 *
 * One statement is already atomic, and the diagnostic read must be conditional
 * on that statement's outcome — which a batch (all statements submitted up
 * front) cannot express. `requireAtomicBatch` is deliberately NOT asserted: this
 * operation is safe on any handle that can run one statement. Same reasoning as
 * `./references-d1.ts`.
 */
import { StorageError } from "../errors.js";
import {
  type SiteDomainVerificationAttempt,
  type SiteDomainVerificationState,
  type StoredSiteDomainVerification,
  siteDomainVerificationAttemptDecision,
  siteDomainVerificationStateFromString,
} from "../site-domain.js";
import { bindOptional, d1Error, optionalNumber, optionalText } from "./rows.js";

/** The projection order shared by every read, matching {@link StoredSiteDomainVerification}. */
export const SITE_DOMAIN_VERIFICATION_COLUMNS =
  "tenant_id, hostname, site, state, challenge_token, issued_at_unix, token_expires_at_unix, " +
  "verified_at_unix, verification_expires_at_unix, last_checked_at_unix, last_failure_reason, " +
  "attempt_count, updated_at_unix";

/**
 * The guarded CAS. The cooldown predicate and the write are ONE statement, so
 * there is no window between deciding the slot is free and taking it.
 *
 * Exported because the mutation proof in `test/d1/site-domain-d1.test.ts`
 * asserts the predicate is present in the SQL the store actually runs — a test
 * that only exercised the outcome would still pass against a read-then-write.
 */
export const BEGIN_SITE_DOMAIN_VERIFICATION_ATTEMPT_SQL =
  "UPDATE site_domain_verifications " +
  "SET last_checked_at_unix = ?, updated_at_unix = ? " +
  "WHERE tenant_id = ? AND hostname = ? " +
  "  AND (last_checked_at_unix IS NULL OR ? - last_checked_at_unix >= ?)";

interface SiteDomainVerificationRow {
  tenant_id: string;
  hostname: string;
  site: string;
  state: string;
  challenge_token: string;
  issued_at_unix: number;
  token_expires_at_unix: number;
  verified_at_unix: number | null;
  verification_expires_at_unix: number | null;
  last_checked_at_unix: number | null;
  last_failure_reason: string | null;
  attempt_count: number;
  updated_at_unix: number;
}

function intoStored(row: SiteDomainVerificationRow): StoredSiteDomainVerification {
  const state: SiteDomainVerificationState | undefined = siteDomainVerificationStateFromString(
    row.state,
  );
  if (state === undefined) {
    // Fail CLOSED on an unknown token rather than defaulting to something
    // servable: a poisoned or partially-migrated row must never be able to
    // authorize a hostname it does not own.
    throw StorageError.runtime(
      `unknown site_domain_verifications.state ${row.state} for ${row.tenant_id}/${row.hostname}`,
    );
  }
  return {
    tenantId: row.tenant_id,
    hostname: row.hostname,
    site: row.site,
    state,
    challengeToken: row.challenge_token,
    issuedAtUnix: Number(row.issued_at_unix),
    tokenExpiresAtUnix: Number(row.token_expires_at_unix),
    verifiedAtUnix: optionalNumber(row.verified_at_unix),
    verificationExpiresAtUnix: optionalNumber(row.verification_expires_at_unix),
    lastCheckedAtUnix: optionalNumber(row.last_checked_at_unix),
    lastFailureReason: optionalText(row.last_failure_reason),
    attemptCount: Number(row.attempt_count),
    updatedAtUnix: Number(row.updated_at_unix),
  };
}

function changes(result: D1Response): number {
  const meta = result.meta as { changes?: number } | undefined;
  return meta?.changes ?? 0;
}

export class D1SiteDomainVerificationStore {
  constructor(private readonly db: D1Database) {}

  /**
   * Reserve the outbound-DNS slot for one `(tenant, hostname)`, or refuse with
   * the remaining cooldown (Rust `try_begin_site_domain_verification_attempt`).
   *
   * A grant means the caller MAY now perform exactly one DNS lookup. The
   * `last_checked_at_unix` write has already happened when this returns
   * `allowed` — that is the reservation, and it is deliberately NOT deferred
   * until after the lookup, because a slot that is only taken on success is a
   * slot an attacker can hold open by making the lookup fail.
   *
   * A `(tenant, hostname)` with NO row at all is `allowed`, matching Rust: there
   * is nothing to rate-limit yet, and the caller is about to create the record.
   * That is not a bypass — the FIRST attempt is always allowed by the pure rule
   * too, and once the row exists the guard applies from then on.
   */
  async tryBeginVerificationAttempt(
    tenantId: string,
    hostname: string,
    nowUnix: number,
    cooldownSecs: number,
  ): Promise<SiteDomainVerificationAttempt> {
    try {
      const guarded = await this.db
        .prepare(BEGIN_SITE_DOMAIN_VERIFICATION_ATTEMPT_SQL)
        .bind(nowUnix, nowUnix, tenantId, hostname, nowUnix, cooldownSecs)
        .run();
      if (changes(guarded) > 0) return { kind: "allowed" };

      // The guard already refused. This read only LABELS the refusal with a
      // retry hint; it can never turn a refusal into a grant, because the grant
      // was the UPDATE's own `changes()`.
      const record = await this.getVerification(tenantId, hostname);
      if (record === undefined) return { kind: "allowed" };
      const decision = siteDomainVerificationAttemptDecision(
        record.lastCheckedAtUnix,
        nowUnix,
        cooldownSecs,
      );
      // A concurrent winner can make the pure decision disagree with the guard
      // (its write landed between the two statements). The guard is the
      // authority: report the refusal with the cooldown that winner started.
      if (decision.kind === "allowed") {
        return {
          kind: "rate_limited",
          retryAfterSecs: Math.max(cooldownSecs, 1),
        };
      }
      return decision;
    } catch (error) {
      throw d1Error("try_begin_site_domain_verification_attempt", error);
    }
  }

  /** One `(tenant, hostname)` verification record, or `undefined`. */
  async getVerification(
    tenantId: string,
    hostname: string,
  ): Promise<StoredSiteDomainVerification | undefined> {
    try {
      const row = await this.db
        .prepare(
          `SELECT ${SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications WHERE tenant_id = ? AND hostname = ?`,
        )
        .bind(tenantId, hostname)
        .first<SiteDomainVerificationRow>();
      return row === null ? undefined : intoStored(row);
    } catch (error) {
      throw d1Error("get_site_domain_verification", error);
    }
  }

  /**
   * Every verification record, optionally narrowed to one tenant, ordered by
   * hostname like Postgres.
   */
  async listVerifications(tenantId?: string): Promise<StoredSiteDomainVerification[]> {
    try {
      const statement =
        tenantId === undefined
          ? this.db.prepare(
              `SELECT ${SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications ORDER BY tenant_id ASC, hostname ASC`,
            )
          : this.db
              .prepare(
                `SELECT ${SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications WHERE tenant_id = ? ORDER BY hostname ASC`,
              )
              .bind(tenantId);
      const rows = await statement.all<SiteDomainVerificationRow>();
      return rows.results.map(intoStored);
    } catch (error) {
      throw d1Error("list_site_domain_verifications", error);
    }
  }

  /**
   * Create or replace one verification record.
   *
   * `last_checked_at_unix` is written from the record like every other column:
   * the reservation is {@link tryBeginVerificationAttempt}'s job, and a caller
   * that reserved a slot and then upserted the post-lookup record (with
   * `markVerified`/`markCheckFailed` already applied) must not have its own
   * `lastCheckedAtUnix` silently discarded — that would reopen the window this
   * class closes.
   */
  async upsertVerification(record: StoredSiteDomainVerification): Promise<void> {
    try {
      await this.db
        .prepare(
          `INSERT INTO site_domain_verifications (${SITE_DOMAIN_VERIFICATION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, hostname) DO UPDATE SET site = excluded.site, state = excluded.state, challenge_token = excluded.challenge_token, issued_at_unix = excluded.issued_at_unix, token_expires_at_unix = excluded.token_expires_at_unix, verified_at_unix = excluded.verified_at_unix, verification_expires_at_unix = excluded.verification_expires_at_unix, last_checked_at_unix = excluded.last_checked_at_unix, last_failure_reason = excluded.last_failure_reason, attempt_count = excluded.attempt_count, updated_at_unix = excluded.updated_at_unix`,
        )
        .bind(
          record.tenantId,
          record.hostname,
          record.site,
          record.state,
          record.challengeToken,
          record.issuedAtUnix,
          record.tokenExpiresAtUnix,
          bindOptional(record.verifiedAtUnix),
          bindOptional(record.verificationExpiresAtUnix),
          bindOptional(record.lastCheckedAtUnix),
          bindOptional(record.lastFailureReason),
          record.attemptCount,
          record.updatedAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("upsert_site_domain_verification", error);
    }
  }

  /** Drop one `(tenant, hostname)` record; `true` when a row was removed. */
  async deleteVerification(tenantId: string, hostname: string): Promise<boolean> {
    try {
      const result = await this.db
        .prepare("DELETE FROM site_domain_verifications WHERE tenant_id = ? AND hostname = ?")
        .bind(tenantId, hostname)
        .run();
      return changes(result) > 0;
    } catch (error) {
      throw d1Error("delete_site_domain_verification", error);
    }
  }
}
