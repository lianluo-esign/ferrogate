/**
 * Phase B (#66, login leg): a per-colo KV PROJECTION of the login bootstrap —
 * `admin_users` (by email) JOINed with the caller's `admin_user_tenant_memberships`
 * — so `POST /v1/admin/login` can resolve its FIRST control read from a replicated
 * KV read instead of an RPC to the single-region singleton {@link
 * import("../store/control-data-object.js")} control object. That RPC is one of the
 * 200–978ms cross-region hops the <1s login SLA cannot afford.
 *
 * Unlike the `api_key_directory` projection (`@ferrogate/storage`), whose READER is
 * a different Worker (the gateway), this projection's reader and writer are BOTH
 * this control-plane Worker — the login handler reads it, and the same handler /
 * team routes populate and invalidate it. It therefore lives here, next to the
 * store whose shape it caches, rather than in the shared storage package.
 *
 * ## This value carries a PASSWORD HASH — deliberately, and here is the envelope
 *
 * Making login DO-free means the cached bootstrap includes `user.passwordHash`, so
 * the KDF check can run against the KV value. This was an explicit decision (the
 * alternative — caching only the tenant mapping and still reading the hash from the
 * control object — keeps a DO round trip on every login). The exposure is bounded
 * on every axis a credential cache must bound:
 *
 *  - **POSITIVE ONLY.** A value is written ONLY for an email the control object
 *    actually holds (the login read-ahead's authoritative-fallback populate). An
 *    unknown email — `bootstrapLoginByEmail` returned `null` — is NEVER written, so
 *    an email-spray cannot seed the cache and a miss is never mistaken for a hit.
 *  - **A CORRUPT ENTRY IS A MISS.** {@link read} returns `null` for absent,
 *    unparseable OR shape-invalid bytes, forcing the authoritative RPC. There is no
 *    path from bad cache bytes to an authenticated session.
 *  - **NEVER LOOSER, ONLY FASTER.** A KV hit does not skip a single check: the
 *    login handler re-runs the `disabledAtUnix` gate, the password KDF and the
 *    membership resolution against the cached value exactly as it does against a
 *    DO read. The worst a stale/forged entry can do is fail those checks (a 401)
 *    or fall through to the authoritative read — it cannot mint a session.
 *  - **INVALIDATE-ON-MUTATION.** Team invite / change-role / revoke DELETE the
 *    affected user's entry, so a membership or tier change ends the window in which
 *    a fresh login could be issued from stale authority — the same promptness the
 *    key directory gets from delete-on-revoke. Any FUTURE route that mutates a
 *    security-relevant `admin_users` field (a password change, an account disable)
 *    MUST delete the entry too; the cosmetic `lastLogin` write is the ONE mutation
 *    that deliberately does not (see the immutable-email note below).
 *  - **A TTL BACKSTOP.** Every write carries an `expirationTtl`, so an entry a
 *    delete somehow missed still self-expires within {@link
 *    DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS} (clamped up to the KV 60s floor).
 *
 * ## Email is treated as immutable
 *
 * The key is the normalized email. `admin_users.email` is `UNIQUE` and is only ever
 * SET at registration in the current surface — no route changes an existing user's
 * email. If an email-change path is ever added it MUST {@link
 * AdminIdentityProjection.delete} the OLD email's key, or a login under the old
 * address could resolve the stale bootstrap until the TTL lapses. The cosmetic
 * `lastLogin` write, by contrast, keeps the same email and is deliberately NOT an
 * invalidation point — treating it as one would delete the entry the same login
 * just populated, defeating the cache on every request.
 */
import type { AdminLoginBootstrap, AdminMembershipRow, AdminUserRow } from "./store.js";

/**
 * The default projection TTL, mirroring the key directory's 30s. The cache is a
 * latency shortcut, not a source of truth, so a short life keeps any entry a
 * mutation-delete missed from lingering.
 */
export const DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS = 30;

/** Cloudflare KV's minimum `expirationTtl`. A write clamps up to this. */
export const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

/** The KV key prefix — namespaced + versioned so the byte format can evolve. */
export const IDENTITY_PROJECTION_PREFIX = "aid:v1:";

/**
 * Normalize an email to the SAME shape the login/register handlers use
 * (`trim().toLowerCase()`), so the writer's key and the reader's key agree. A
 * mismatch here is not a security hole — it is a silent cache MISS that quietly
 * reinstates the DO read — which is exactly why it is centralized in one function.
 */
export function normalizeIdentityEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** The KV key an identity bootstrap is stored under, derived from its email. */
export function adminIdentityProjectionKey(email: string): string {
  return `${IDENTITY_PROJECTION_PREFIX}${normalizeIdentityEmail(email)}`;
}

/**
 * The seam the login read-ahead, its authoritative-fallback populate, and the
 * team-route invalidations all depend on. Injected so every side is testable
 * without a real KV binding, and so `consoleOf` stays inject-free (no binding ⇒
 * pure RPC, exactly as before this slice).
 */
export interface AdminIdentityProjection {
  /** A cached bootstrap, or `null` for absent / unparseable / shape-invalid bytes. */
  read(email: string): Promise<AdminLoginBootstrap | null>;
  /** Upsert a POSITIVE bootstrap under `email`, with the TTL backstop. */
  write(email: string, bootstrap: AdminLoginBootstrap): Promise<void>;
  /** Drop the entry for `email` (invite / change-role / revoke). */
  delete(email: string): Promise<void>;
}

/**
 * The KV surface this module needs — narrower than `KVNamespace` on purpose, so a
 * test double is a three-method object and this module reaches no method a
 * projection has no business calling.
 */
export interface IdentityDirectoryKv {
  get(key: string, type: "text"): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface KvAdminIdentityProjectionOptions {
  /** TTL in seconds; clamped up to {@link KV_MIN_EXPIRATION_TTL_SECONDS} for KV. */
  readonly ttlSeconds?: number;
}

/** Turn arbitrary decoded JSON into an {@link AdminUserRow}, or `null` (a MISS). */
function toUser(value: unknown): AdminUserRow | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (
    typeof v.id !== "string" ||
    typeof v.email !== "string" ||
    typeof v.passwordHash !== "string" ||
    typeof v.displayName !== "string" ||
    typeof v.superadmin !== "boolean" ||
    typeof v.createdAtUnix !== "number" ||
    typeof v.updatedAtUnix !== "number"
  ) {
    return null;
  }
  const lastLogin = v.lastLoginAtUnix;
  const disabled = v.disabledAtUnix;
  if (!(lastLogin === null || typeof lastLogin === "number")) return null;
  if (!(disabled === null || typeof disabled === "number")) return null;
  return {
    id: v.id,
    email: v.email,
    passwordHash: v.passwordHash,
    displayName: v.displayName,
    superadmin: v.superadmin,
    createdAtUnix: v.createdAtUnix,
    updatedAtUnix: v.updatedAtUnix,
    lastLoginAtUnix: lastLogin,
    disabledAtUnix: disabled,
  };
}

/** Turn one decoded membership into an {@link AdminMembershipRow}, or `null`. */
function toMembership(value: unknown): AdminMembershipRow | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (
    typeof v.id !== "string" ||
    typeof v.userId !== "string" ||
    typeof v.tenantId !== "string" ||
    typeof v.role !== "string" ||
    typeof v.createdAtUnix !== "number"
  ) {
    return null;
  }
  return {
    id: v.id,
    userId: v.userId,
    tenantId: v.tenantId,
    role: v.role,
    createdAtUnix: v.createdAtUnix,
  };
}

/**
 * Turn decoded JSON into an {@link AdminLoginBootstrap}, or `null`. Strict about
 * every field, and about the memberships being an array of well-formed rows: one
 * malformed membership fails the WHOLE value (a MISS), because login takes
 * `memberships[0]` and a silently-dropped member could change the tier a user
 * lands in. This strictness is the read side's whole fail-closed guarantee.
 */
function toBootstrap(value: unknown): AdminLoginBootstrap | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  const user = toUser(v.user);
  if (user === null) return null;
  if (!Array.isArray(v.memberships)) return null;
  const memberships: AdminMembershipRow[] = [];
  for (const raw of v.memberships) {
    const membership = toMembership(raw);
    if (membership === null) return null;
    memberships.push(membership);
  }
  return { user, memberships };
}

/** The stored value — exactly the bootstrap columns, nothing wider. */
function serialize(bootstrap: AdminLoginBootstrap): string {
  return JSON.stringify({
    user: {
      id: bootstrap.user.id,
      email: bootstrap.user.email,
      passwordHash: bootstrap.user.passwordHash,
      displayName: bootstrap.user.displayName,
      superadmin: bootstrap.user.superadmin,
      createdAtUnix: bootstrap.user.createdAtUnix,
      updatedAtUnix: bootstrap.user.updatedAtUnix,
      lastLoginAtUnix: bootstrap.user.lastLoginAtUnix,
      disabledAtUnix: bootstrap.user.disabledAtUnix,
    },
    memberships: bootstrap.memberships.map((m) => ({
      id: m.id,
      userId: m.userId,
      tenantId: m.tenantId,
      role: m.role,
      createdAtUnix: m.createdAtUnix,
    })),
  });
}

/** {@link AdminIdentityProjection} over a real KV namespace. */
export class KvAdminIdentityProjection implements AdminIdentityProjection {
  readonly #kv: IdentityDirectoryKv;
  readonly #expirationTtl: number;

  constructor(kv: IdentityDirectoryKv, options: KvAdminIdentityProjectionOptions = {}) {
    this.#kv = kv;
    const ttl = options.ttlSeconds ?? DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS;
    const floored = Number.isFinite(ttl)
      ? Math.floor(ttl)
      : DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS;
    this.#expirationTtl = Math.max(floored, KV_MIN_EXPIRATION_TTL_SECONDS);
  }

  async read(email: string): Promise<AdminLoginBootstrap | null> {
    const raw = await this.#kv.get(adminIdentityProjectionKey(email), "text");
    if (raw === null) return null;
    let decoded: unknown;
    try {
      decoded = JSON.parse(raw);
    } catch {
      return null;
    }
    return toBootstrap(decoded);
  }

  async write(email: string, bootstrap: AdminLoginBootstrap): Promise<void> {
    await this.#kv.put(adminIdentityProjectionKey(email), serialize(bootstrap), {
      expirationTtl: this.#expirationTtl,
    });
  }

  async delete(email: string): Promise<void> {
    await this.#kv.delete(adminIdentityProjectionKey(email));
  }
}
