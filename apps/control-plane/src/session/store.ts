/**
 * The admin-console identity store — `admin_users`,
 * `admin_user_tenant_memberships` and `admin_user_refresh_tokens` in the
 * CONTROL database.
 *
 * ## What this closes
 *
 * All three tables have shipped in `sql/d1-ts/control/0001_init_control.sql`
 * since the first migration, complete with the `role` CHECK the migration's own
 * comment calls "a DELIBERATE EXCEPTION" because the column is a privilege
 * tier. **Nothing in TypeScript ever read or wrote one of them.** They are the
 * same DURABLE-BUT-UNREAD shape as the virtual-key credential rows and the
 * self-hosted-worker registry: a schema with no reader on one side and no
 * writer on the other, invisible to every green suite.
 *
 * These are TYPED tables, not `control_plane_resources` documents, so they are
 * reached through `deps.controlDatabase` rather than through
 * {@link import("../ports.js").ControlPlaneStore}. That split is the same one
 * `store/worker_registry.ts` documents: the document store is a swappable
 * abstraction, while a row another surface joins on by column name is not.
 *
 * ## Tenant scoping
 *
 * These tables are deliberately account-global and are NOT tenant-fenced at the
 * SQL level, because the identity they hold spans tenants by construction: one
 * human belongs to several tenants (`admin_user_tenant_memberships` is the
 * many-to-many), and the lookup that RESOLVES which tenant a session belongs to
 * cannot itself be tenant-scoped. The fence is one layer up and is enforced on
 * every read: `currentAdminSession` only ever returns the membership matching
 * the session JWT's own `tenant_id` claim, and every team endpoint operates on
 * `membership.tenantId` — never on a tenant id taken from the request.
 */
import type { MembershipRole } from "./membership_role.js";

/** `admin_users`, column for column (Rust `StoredAdminUser`). */
export interface AdminUserRow {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly displayName: string;
  readonly superadmin: boolean;
  readonly createdAtUnix: number;
  readonly updatedAtUnix: number;
  readonly lastLoginAtUnix: number | null;
  readonly disabledAtUnix: number | null;
}

/** `admin_user_tenant_memberships` (Rust `StoredAdminUserMembership`). */
export interface AdminMembershipRow {
  readonly id: string;
  readonly userId: string;
  readonly tenantId: string;
  /** The RAW stored string. Callers resolve it with `membershipRoleFromStored`. */
  readonly role: string;
  readonly createdAtUnix: number;
}

/** `admin_user_refresh_tokens` (Rust `StoredAdminUserRefreshToken`). */
export interface AdminRefreshTokenRow {
  readonly id: string;
  readonly userId: string;
  readonly tokenHash: string;
  /** `null` on rows predating tenant-scoped sessions (#232) — those fail closed. */
  readonly tenantId: string | null;
  readonly role: string | null;
  readonly createdAtUnix: number;
  readonly expiresAtUnix: number;
  readonly revokedAtUnix: number | null;
}

/**
 * The narrow persistence surface the session routes talk to.
 *
 * One method per Rust repository call, deliberately: unlike the 200 CRUD
 * operations, this is nine routes over three tables with fixed access patterns,
 * and a generic document interface here would hide the two lookups that MUST be
 * indexed point reads (`email`, `token_hash`) behind a scan.
 */
export interface AdminConsoleSessionStore {
  getUserByEmail(email: string): Promise<AdminUserRow | null>;
  getUserById(id: string): Promise<AdminUserRow | null>;
  upsertUser(user: AdminUserRow): Promise<void>;
  listMembershipsByUser(userId: string): Promise<readonly AdminMembershipRow[]>;
  listMembershipsByTenant(tenantId: string): Promise<readonly AdminMembershipRow[]>;
  upsertMembership(membership: AdminMembershipRow): Promise<void>;
  /** `true` when a row was removed. Rust `delete_admin_user_membership`. */
  deleteMembership(userId: string, tenantId: string): Promise<boolean>;
  getRefreshTokenByHash(tokenHash: string): Promise<AdminRefreshTokenRow | null>;
  upsertRefreshToken(token: AdminRefreshTokenRow): Promise<void>;
}

function bit(value: boolean): number {
  return value ? 1 : 0;
}

function nullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function nullableText(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

interface RawUser {
  id: string;
  email: string;
  password_hash: string;
  display_name: string;
  superadmin: number;
  created_at_unix: number;
  updated_at_unix: number;
  last_login_at_unix: number | null;
  disabled_at_unix: number | null;
}

function decodeUser(row: RawUser): AdminUserRow {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    displayName: row.display_name,
    superadmin: row.superadmin === 1,
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
    lastLoginAtUnix: nullableNumber(row.last_login_at_unix),
    disabledAtUnix: nullableNumber(row.disabled_at_unix),
  };
}

interface RawMembership {
  id: string;
  user_id: string;
  tenant_id: string;
  role: string;
  created_at_unix: number;
}

function decodeMembership(row: RawMembership): AdminMembershipRow {
  return {
    id: row.id,
    userId: row.user_id,
    tenantId: row.tenant_id,
    role: row.role,
    createdAtUnix: row.created_at_unix,
  };
}

interface RawRefreshToken {
  id: string;
  user_id: string;
  token_hash: string;
  tenant_id: string | null;
  role: string | null;
  created_at_unix: number;
  expires_at_unix: number;
  revoked_at_unix: number | null;
}

function decodeRefreshToken(row: RawRefreshToken): AdminRefreshTokenRow {
  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    tenantId: nullableText(row.tenant_id),
    role: nullableText(row.role),
    createdAtUnix: row.created_at_unix,
    expiresAtUnix: row.expires_at_unix,
    revokedAtUnix: nullableNumber(row.revoked_at_unix),
  };
}

/** The D1 implementation. The only one — there is no in-memory twin, on purpose. */
export class D1AdminConsoleSessionStore implements AdminConsoleSessionStore {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async getUserByEmail(email: string): Promise<AdminUserRow | null> {
    const row = await this.#db
      .prepare("SELECT * FROM admin_users WHERE email = ?")
      .bind(email)
      .first<RawUser>();
    return row === null ? null : decodeUser(row);
  }

  async getUserById(id: string): Promise<AdminUserRow | null> {
    const row = await this.#db
      .prepare("SELECT * FROM admin_users WHERE id = ?")
      .bind(id)
      .first<RawUser>();
    return row === null ? null : decodeUser(row);
  }

  async upsertUser(user: AdminUserRow): Promise<void> {
    await this.#db
      .prepare(
        `INSERT INTO admin_users (
           id, email, password_hash, display_name, superadmin,
           created_at_unix, updated_at_unix, last_login_at_unix, disabled_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           email = excluded.email,
           password_hash = excluded.password_hash,
           display_name = excluded.display_name,
           superadmin = excluded.superadmin,
           updated_at_unix = excluded.updated_at_unix,
           last_login_at_unix = excluded.last_login_at_unix,
           disabled_at_unix = excluded.disabled_at_unix`,
      )
      .bind(
        user.id,
        user.email,
        user.passwordHash,
        user.displayName,
        bit(user.superadmin),
        user.createdAtUnix,
        user.updatedAtUnix,
        user.lastLoginAtUnix,
        user.disabledAtUnix,
      )
      .run();
  }

  /**
   * Ordered `created_at_unix, id` — OLDEST FIRST, and the order is load-bearing.
   *
   * Rust's login takes `memberships.first()`, i.e. the user's oldest
   * membership, and the whole point of #232 is that REFRESH must NOT do that.
   * An unordered `SELECT` would make "oldest" whatever SQLite felt like, so the
   * login tier a user gets could change between two identical requests. `id` is
   * the tiebreaker because two memberships can share a second.
   */
  async listMembershipsByUser(userId: string): Promise<readonly AdminMembershipRow[]> {
    const rows = await this.#db
      .prepare(
        `SELECT * FROM admin_user_tenant_memberships
          WHERE user_id = ? ORDER BY created_at_unix ASC, id ASC`,
      )
      .bind(userId)
      .all<RawMembership>();
    return rows.results.map(decodeMembership);
  }

  async listMembershipsByTenant(tenantId: string): Promise<readonly AdminMembershipRow[]> {
    const rows = await this.#db
      .prepare(
        `SELECT * FROM admin_user_tenant_memberships
          WHERE tenant_id = ? ORDER BY created_at_unix ASC, id ASC`,
      )
      .bind(tenantId)
      .all<RawMembership>();
    return rows.results.map(decodeMembership);
  }

  /**
   * Upsert on `(user_id, tenant_id)` — the table's UNIQUE constraint — NOT on
   * `id`. Re-inviting an existing member must change their role, and an
   * `ON CONFLICT (id)` upsert of a freshly minted id would instead violate the
   * UNIQUE pair and fail the whole call.
   */
  async upsertMembership(membership: AdminMembershipRow): Promise<void> {
    await this.#db
      .prepare(
        `INSERT INTO admin_user_tenant_memberships (id, user_id, tenant_id, role, created_at_unix)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = excluded.role`,
      )
      .bind(
        membership.id,
        membership.userId,
        membership.tenantId,
        membership.role,
        membership.createdAtUnix,
      )
      .run();
  }

  async deleteMembership(userId: string, tenantId: string): Promise<boolean> {
    const result = await this.#db
      .prepare("DELETE FROM admin_user_tenant_memberships WHERE user_id = ? AND tenant_id = ?")
      .bind(userId, tenantId)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async getRefreshTokenByHash(tokenHash: string): Promise<AdminRefreshTokenRow | null> {
    const row = await this.#db
      .prepare("SELECT * FROM admin_user_refresh_tokens WHERE token_hash = ?")
      .bind(tokenHash)
      .first<RawRefreshToken>();
    return row === null ? null : decodeRefreshToken(row);
  }

  async upsertRefreshToken(token: AdminRefreshTokenRow): Promise<void> {
    await this.#db
      .prepare(
        `INSERT INTO admin_user_refresh_tokens (
           id, user_id, token_hash, tenant_id, role,
           created_at_unix, expires_at_unix, revoked_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           tenant_id = excluded.tenant_id,
           role = excluded.role,
           expires_at_unix = excluded.expires_at_unix,
           revoked_at_unix = excluded.revoked_at_unix`,
      )
      .bind(
        token.id,
        token.userId,
        token.tokenHash,
        token.tenantId,
        token.role,
        token.createdAtUnix,
        token.expiresAtUnix,
        token.revokedAtUnix,
      )
      .run();
  }
}

/** A membership's tier, resolved. Re-exported so callers need one import. */
export type { MembershipRole };
