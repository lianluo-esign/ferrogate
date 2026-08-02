/**
 * The admin-console SESSION surface: `/v1/admin/*`.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/admin_console.rs`
 * (1481 lines) as specified by `admin_console_test.rs` (3780 lines — the
 * largest test file in the Rust tree), routed exactly as
 * `ferrogate-auth-service/src/server.rs` routes it:
 *
 * | route                                        | Rust handler                   |
 * |----------------------------------------------|--------------------------------|
 * | `POST   /v1/admin/register`                  | `handle_admin_register`        |
 * | `POST   /v1/admin/login`                     | `handle_admin_login`           |
 * | `POST   /v1/admin/refresh`                   | `handle_admin_refresh`         |
 * | `POST   /v1/admin/logout`                    | `handle_admin_logout`          |
 * | `GET    /v1/admin/me`                        | `handle_admin_me`              |
 * | `GET    /v1/admin/team`                      | `handle_admin_team_list`       |
 * | `POST   /v1/admin/team/invite`               | `handle_admin_team_invite`     |
 * | `POST   /v1/admin/team/members/{user_id}`    | `handle_admin_team_change_role`|
 * | `DELETE /v1/admin/team/members/{user_id}`    | `handle_admin_team_revoke`     |
 *
 * ## These are NOT contract operations, and that is correct
 *
 * `docs/openapi/runtime-api-contract.json` has 259 operations and none of them
 * is `/v1/admin/login` — the contract describes the GATEWAY runtime API, while
 * this is the auth SERVICE's own surface, which the Rust tree served from a
 * separate binary on a separate port. `PORT-PLAN.md` folds
 * `ferrogate-auth-service` into `apps/control-plane`, and `src/index.ts`'s
 * docblock has always listed `/v1/admin/*` as "still to come on this Worker".
 * So they mount OUTSIDE `registerRoutes`, exactly as `/healthz` and `/version`
 * do, and cannot move the anti-drift operation count.
 *
 * ## CSRF is applied here explicitly, because `contractAuth` cannot
 *
 * `contractAuth` runs `adminCrossSiteRejection` only after it has MATCHED a
 * contract operation; a path that is not one of the 200 is waved straight
 * through. `/v1/admin/login` is a state-changing browser endpoint that mints a
 * credential, so it must carry the same guard, and {@link consoleCsrf} below is
 * that guard — the same function `middleware/auth.ts` exports, not a second
 * copy of the rule.
 *
 * ## There is no cookie, and there is no `Set-Cookie`
 *
 * The Rust surface is a pure bearer-token API: the access token is a JWT the
 * client presents as `Authorization: Bearer`, and the refresh token travels in
 * a JSON request body. `admin_console.rs` contains no cookie handling at all,
 * so there is no `SameSite`/`Secure`/`HttpOnly` to preserve. Introducing a
 * session cookie here would be a NEW security surface, not a port, and it is
 * deliberately not done.
 */
import type { Context, Hono } from "hono";
import { z } from "zod";
import { adminCrossSiteRejection, isStateChangingMethod } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, ControlPlaneEnv, StoreRecord } from "../ports.js";
import {
  PROJECTS_COLLECTION,
  TENANT_ACCOUNTS_COLLECTION,
  WORKSPACES_COLLECTION,
} from "../store/lifecycle.js";
import {
  generateRefreshTokenSecret,
  hashPassword,
  isValidEmail,
  nextId,
  slugifyWithSuffix,
  verifyPassword,
} from "./credentials.js";
import {
  provisionGatewayApiKey,
  requireUsableConsoleTenancy,
  revokeAdminConsoleSessionKeys,
} from "./gateway_key.js";
import {
  type MembershipRole,
  acceptedMembershipRoles,
  isOwner,
  membershipRoleFromStored,
  parseMembershipRole,
} from "./membership_role.js";
import {
  type AdminConsoleSessionStore,
  type AdminMembershipRow,
  type AdminUserRow,
  D1AdminConsoleSessionStore,
} from "./store.js";
import {
  ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
  ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
  signAdminAccessToken,
  verifyAdminAccessToken,
} from "./tokens.js";

type Ctx = Context<ControlPlaneEnv>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * The console session signing secret.
 *
 * `ports.ts` already carries the PORT-TODO explaining why this cannot come from
 * Secrets Store from inside a Worker (a `[[secrets_store_secrets]]` binding is
 * resolved at DEPLOY time and there is no offline runtime fetch). It is a
 * `wrangler secret` for now.
 */
export const ADMIN_CONSOLE_JWT_SECRET_BINDING = "ADMIN_CONSOLE_JWT_SECRET";

interface ConsoleContext {
  readonly deps: ControlPlaneDeps;
  readonly store: AdminConsoleSessionStore;
  readonly jwtSecret: string;
}

/**
 * Resolve the surface's two hard requirements, or refuse.
 *
 * **503, never a degraded session.** Without a signing secret every token would
 * have to be signed with something — a constant, an empty string, a per-isolate
 * random value — and each of those is worse than being down: the first two are
 * forgeable by anyone who reads the source, and the third silently invalidates
 * every session on isolate eviction. Without the control database there are no
 * `admin_users` rows to authenticate against at all.
 */
function consoleOf(c: Ctx): ConsoleContext {
  const deps = c.get("deps") as ControlPlaneDeps;
  const secret = (c.env as unknown as Record<string, unknown>)[ADMIN_CONSOLE_JWT_SECRET_BINDING];
  const jwtSecret = typeof secret === "string" ? secret.trim() : "";
  if (jwtSecret === "") {
    throw new HttpError(
      503,
      "admin_console_unconfigured",
      `admin console sessions require the ${ADMIN_CONSOLE_JWT_SECRET_BINDING} secret binding`,
    );
  }
  if (deps.controlDatabase === null) {
    throw new HttpError(
      503,
      "admin_console_unconfigured",
      "admin console sessions require the control database binding DB",
    );
  }
  return { deps, store: new D1AdminConsoleSessionStore(deps.controlDatabase), jwtSecret };
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

const registerSchema = z.object({
  organization_name: z.string(),
  email: z.string(),
  password: z.string(),
  display_name: z.string().nullish(),
});
const loginSchema = z.object({ email: z.string(), password: z.string() });
const refreshSchema = z.object({ refresh_token: z.string() });
const inviteSchema = z.object({ email: z.string(), role: z.string() });
const changeRoleSchema = z.object({ role: z.string() });

/**
 * Rust `bad_request(serde_json::Error)` → 400 `invalid_json`, distinct from the
 * 422 `invalid_request` a well-formed but unacceptable body gets. The
 * distinction is the client's: one is "your serializer is broken", the other is
 * "your value is not allowed".
 */
async function readBody<T>(c: Ctx, schema: z.ZodType<T>): Promise<T> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch (error) {
    throw new HttpError(
      400,
      "invalid_json",
      error instanceof Error ? error.message : "request body is not valid JSON",
    );
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new HttpError(422, "invalid_request", parsed.error.issues[0]?.message ?? "invalid body");
  }
  return parsed.data;
}

/** Rust `unprocessable`. */
function unprocessable(message: string): HttpError {
  return new HttpError(422, "invalid_request", message);
}

/**
 * Rust `bearer_token`: `Authorization: Bearer <jwt>` ONLY.
 *
 * Deliberately NOT `middleware/auth.ts`'s `extractApiKey`, which prefers
 * `x-api-key`: that header carries a GATEWAY API key, a different credential
 * with a different verifier, and accepting one here would let an
 * `admin.read` virtual key be presented where a session JWT is expected.
 */
function bearerToken(c: Ctx): string {
  const authorization = c.req.header("authorization")?.trim() ?? "";
  if (!authorization.startsWith("Bearer ")) {
    throw new HttpError(401, "unauthorized", "missing bearer token");
  }
  const token = authorization.slice("Bearer ".length).trim();
  if (token === "") throw new HttpError(401, "unauthorized", "missing bearer token");
  return token;
}

// ---------------------------------------------------------------------------
// Session issuance
// ---------------------------------------------------------------------------

interface IssuedSession {
  readonly accessToken: string;
  readonly refreshToken: string;
}

/** Rust `issue_session` — the access JWT plus a durable, HASHED refresh row. */
async function issueSession(
  console_: ConsoleContext,
  user: { id: string; email: string },
  tenantId: string,
  role: MembershipRole,
): Promise<IssuedSession> {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = await signAdminAccessToken(console_.jwtSecret, {
    sub: user.id,
    email: user.email,
    tenant_id: tenantId,
    role,
    iat: now,
    exp: now + ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
  });
  const refreshToken = generateRefreshTokenSecret();
  await console_.store.upsertRefreshToken({
    id: nextId("rt"),
    userId: user.id,
    // Stored HASHED, never plaintext, so a durable-storage read cannot itself
    // mint a session. Same construction the gateway's key directory uses.
    tokenHash: await hashRefreshToken(refreshToken),
    // Stamp the tenant/role this session was issued for (#232), so a later
    // refresh re-issues for the SAME tenant instead of whichever membership
    // happens to sort first.
    tenantId,
    role,
    createdAtUnix: now,
    expiresAtUnix: now + ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
    revokedAtUnix: null,
  });
  return { accessToken, refreshToken };
}

/** Rust `hash_virtual_api_key_secret`, the construction every FerroGate hash uses. */
async function hashRefreshToken(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret.trim()));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

function userView(user: AdminUserRow): Record<string, unknown> {
  return { id: user.id, email: user.email, display_name: user.displayName };
}

// ---------------------------------------------------------------------------
// The session gate every authenticated console route runs
// ---------------------------------------------------------------------------

/**
 * Rust `current_admin_session`: the caller's user AND their membership in the
 * tenant their session was issued for.
 *
 * Three refusals, in order, and none of them may be skipped:
 *
 *  1. the token must verify (signature, algorithm, expiry);
 *  2. the account must still exist and the membership named by the token's
 *     `tenant_id` claim must still exist — never `memberships.first()`, which
 *     would hand a multi-tenant user another tenant's authority;
 *  3. the #514 tenancy lifecycle gate, on the Recovery seam. Without it a
 *     suspended tenant's console session kept working for its full TTL and
 *     could keep re-issuing itself through `POST /v1/admin/refresh`.
 */
async function currentAdminSession(
  console_: ConsoleContext,
  token: string,
): Promise<{ user: AdminUserRow; membership: AdminMembershipRow }> {
  const claims = await verifyAdminAccessToken(console_.jwtSecret, token);
  // ONE answer for a forged signature, a wrong algorithm, an expired token and
  // a malformed one — the token's state is not disclosed.
  if (claims === null) {
    throw new HttpError(401, "unauthorized", "invalid or expired access token");
  }
  const user = await console_.store.getUserById(claims.sub);
  if (user === null) throw new HttpError(401, "unauthorized", "account no longer exists");
  const memberships = await console_.store.listMembershipsByUser(user.id);
  const membership = memberships.find((candidate) => candidate.tenantId === claims.tenant_id);
  if (membership === undefined) {
    throw new HttpError(401, "unauthorized", "session tenant membership no longer exists");
  }
  await requireUsableConsoleTenancy(console_.deps, {
    tenantId: membership.tenantId,
    userId: user.id,
  });
  return { user, membership };
}

/** Rust's owner-only gate on the team endpoints. */
function requireOwner(membership: AdminMembershipRow, action: string): void {
  if (!isOwner(membershipRoleFromStored(membership.role))) {
    throw new HttpError(403, "forbidden", `only a tenant owner can ${action}`);
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const PLATFORM: { readonly kind: "platform_operator" } = { kind: "platform_operator" };

/**
 * `POST /v1/admin/register` — Rust `handle_admin_register` (#157).
 *
 * Creates the tenant/project/workspace hierarchy, the owning admin user, and a
 * durable gateway virtual key, then issues a session — all in one call, so the
 * console has everything it needs to manage its own tenant immediately.
 *
 * The hierarchy is written as the SAME `tenant-accounts` / `projects` /
 * `workspaces` documents `routes/tenant_hierarchy.ts` writes, which is what
 * makes the new tenant visible to the admin API and, more importantly, to the
 * lifecycle gate: a hierarchy written anywhere else would be a tenant that
 * could never be suspended.
 */
async function handleRegister(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const payload = await readBody(c, registerSchema);

  const email = payload.email.trim().toLowerCase();
  const organizationName = payload.organization_name.trim();
  const displayNameInput = payload.display_name?.trim() ?? "";
  const displayName = displayNameInput === "" ? email : displayNameInput;

  if (!isValidEmail(email)) throw unprocessable("email must be a valid address");
  if (organizationName === "") throw unprocessable("organization_name must not be empty");
  if (payload.password.length < 8) throw unprocessable("password must be at least 8 characters");

  if ((await console_.store.getUserByEmail(email)) !== null) {
    throw new HttpError(409, "conflict", "an account with this email already exists");
  }

  const passwordHash = await hashPassword(payload.password);
  const now = Math.floor(Date.now() / 1000);
  const tenantId = nextId("tenant");
  const projectId = nextId("project");
  const workspaceId = nextId("workspace");
  const userId = nextId("user");

  const store = console_.deps.store;
  await store.create(TENANT_ACCOUNTS_COLLECTION, PLATFORM, {
    id: tenantId,
    tenant_id: tenantId,
    name: organizationName,
    slug: slugifyWithSuffix(organizationName, tenantId),
    status: "active",
    plan_id: "free",
    created_at: now,
    updated_at: now,
  } satisfies StoreRecord);
  await store.create(PROJECTS_COLLECTION, PLATFORM, {
    id: projectId,
    tenant_id: tenantId,
    name: "Default",
    slug: "default",
    status: "active",
    created_at: now,
    updated_at: now,
  } satisfies StoreRecord);
  await store.create(WORKSPACES_COLLECTION, PLATFORM, {
    id: workspaceId,
    tenant_id: tenantId,
    project_id: projectId,
    name: "Default",
    slug: "default",
    environment: "production",
    status: "active",
    created_at: now,
    updated_at: now,
  } satisfies StoreRecord);

  await console_.store.upsertUser({
    id: userId,
    email,
    passwordHash,
    displayName,
    superadmin: false,
    createdAtUnix: now,
    updatedAtUnix: now,
    lastLoginAtUnix: now,
    disabledAtUnix: null,
  });
  // Registration always creates the tenant's first owner.
  await console_.store.upsertMembership({
    id: nextId("membership"),
    userId,
    tenantId,
    role: "owner",
    createdAtUnix: now,
  });

  // #514: a suspended/deleted tenancy is a 403 with the gateway's own code —
  // and, crucially, NOT a live `fg_...` secret. `provisionGatewayApiKey`
  // throws before minting.
  const gatewayApiKey = await provisionGatewayApiKey(console_.deps, {
    tenantId,
    projectId,
    workspaceId,
    adminUserId: userId,
    role: "owner",
  });

  const session = await issueSession(console_, { id: userId, email }, tenantId, "owner");
  return c.json(
    {
      access_token: session.accessToken,
      refresh_token: session.refreshToken,
      expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
      user: { id: userId, email, display_name: displayName },
      tenant: { id: tenantId, name: organizationName, role: "owner" },
      gateway_api_key: gatewayApiKey,
    },
    201,
  );
}

/** `POST /v1/admin/login` — Rust `handle_admin_login`. */
async function handleLogin(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const payload = await readBody(c, loginSchema);
  const email = payload.email.trim().toLowerCase();

  const user = await console_.store.getUserByEmail(email);
  // An unknown email and a wrong password get the SAME answer. Distinguishing
  // them turns this endpoint into an account-enumeration oracle.
  if (user === null) throw new HttpError(401, "unauthorized", "invalid email or password");
  if (user.disabledAtUnix !== null) {
    throw new HttpError(401, "unauthorized", "this account has been disabled");
  }
  if (!(await verifyPassword(payload.password, user.passwordHash))) {
    throw new HttpError(401, "unauthorized", "invalid email or password");
  }

  const memberships = await console_.store.listMembershipsByUser(user.id);
  const membership = memberships[0];
  if (membership === undefined) {
    throw new HttpError(401, "unauthorized", "this account has no tenant membership");
  }
  const tenantAccount = await console_.deps.store.get(
    TENANT_ACCOUNTS_COLLECTION,
    PLATFORM,
    membership.tenantId,
  );
  if (tenantAccount === null) {
    throw new HttpError(
      500,
      "internal_error",
      "tenant account for this membership no longer exists",
    );
  }
  const workspace = await resolveDefaultWorkspace(console_.deps, membership.tenantId);
  if (workspace === null) {
    throw new HttpError(500, "internal_error", "no workspace found for this tenant");
  }

  // The tier is derived from the caller's membership in THIS tenant (#517).
  // `membershipRoleFromStored` resolves an unrecognised legacy value to
  // `viewer`, the least privilege, so a role string that predates the validator
  // can never mint `admin.write`.
  const sessionRole = membershipRoleFromStored(membership.role);
  // Mints a FRESH key and revokes the caller's prior session keys for this
  // tenant, which is what makes the ladder retroactive rather than
  // forward-only. Consequence, deliberately: one browser session per user per
  // tenant — signing in again displaces the previous tab's GATEWAY key. The
  // refresh token is untouched, so the console session itself survives.
  const gatewayApiKey = await provisionGatewayApiKey(console_.deps, {
    tenantId: membership.tenantId,
    projectId: String(workspace.project_id ?? ""),
    workspaceId: String(workspace.id),
    adminUserId: user.id,
    role: sessionRole,
  });

  await console_.store.upsertUser({ ...user, lastLoginAtUnix: Math.floor(Date.now() / 1000) });

  const session = await issueSession(console_, user, membership.tenantId, sessionRole);
  return c.json(
    {
      access_token: session.accessToken,
      refresh_token: session.refreshToken,
      expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
      user: userView(user),
      tenant: {
        id: String(tenantAccount.id),
        name: String(tenantAccount.name ?? ""),
        // The tier the session ACTUALLY got — the same resolved value the
        // gateway key above was scoped from. Reporting the raw stored string
        // would advertise an authority the key does not carry.
        role: sessionRole,
      },
      gateway_api_key: gatewayApiKey,
    },
    200,
  );
}

/** Rust `resolve_default_workspace`: the tenant's first workspace. */
async function resolveDefaultWorkspace(
  deps: ControlPlaneDeps,
  tenantId: string,
): Promise<StoreRecord | null> {
  const page = await deps.store.list(
    WORKSPACES_COLLECTION,
    { kind: "tenant", tenantId },
    { offset: 0, limit: 1000, paginate: false, search: null, filters: {} },
  );
  return page.items.find((item) => item.tenant_id === tenantId) ?? null;
}

/** `POST /v1/admin/refresh` — Rust `handle_admin_refresh` (#232, #514). */
async function handleRefresh(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const payload = await readBody(c, refreshSchema);

  const stored = await console_.store.getRefreshTokenByHash(
    await hashRefreshToken(payload.refresh_token),
  );
  if (stored === null) throw new HttpError(401, "unauthorized", "invalid refresh token");
  const now = Math.floor(Date.now() / 1000);
  if (stored.revokedAtUnix !== null || stored.expiresAtUnix <= now) {
    throw new HttpError(401, "unauthorized", "refresh token has expired or been revoked");
  }
  // ROTATION: the presented token is spent here, before anything else can fail
  // and before a new one exists. A refresh token that survived its own
  // redemption would be a replayable 30-day credential.
  await console_.store.upsertRefreshToken({ ...stored, revokedAtUnix: now });

  const user = await console_.store.getUserById(stored.userId);
  if (user === null) throw new HttpError(401, "unauthorized", "account no longer exists");
  if (user.disabledAtUnix !== null) {
    throw new HttpError(401, "unauthorized", "this account has been disabled");
  }
  // Re-issue for the tenant this token's session was minted for (#232) — NOT
  // `memberships.first()`, which is merely the user's oldest membership and
  // silently swapped a multi-tenant user into the wrong tenant/role on refresh.
  // Legacy rows without a stamped tenant are rejected (fail closed): guessing a
  // tenant would recreate the confusion.
  if (stored.tenantId === null) {
    throw new HttpError(
      401,
      "unauthorized",
      "this refresh token predates tenant-scoped sessions; please sign in again",
    );
  }
  const memberships = await console_.store.listMembershipsByUser(user.id);
  // The CURRENT membership in the stamped tenant, not the stamped role: a
  // demotion takes effect on the next refresh, and a revoked membership ends
  // the session entirely.
  const membership = memberships.find((candidate) => candidate.tenantId === stored.tenantId);
  if (membership === undefined) {
    throw new HttpError(
      401,
      "unauthorized",
      "this account is no longer a member of the session's tenant",
    );
  }
  // #514: refresh is the endpoint that keeps a console session alive
  // indefinitely, so gating login without gating refresh would bound the bypass
  // only by the access token's TTL.
  await requireUsableConsoleTenancy(console_.deps, {
    tenantId: membership.tenantId,
    userId: user.id,
  });

  const session = await issueSession(
    console_,
    user,
    membership.tenantId,
    membershipRoleFromStored(membership.role),
  );
  // Rust returns the three token fields ONLY — no gateway key. Refresh does not
  // re-mint one, so the browser keeps the key its last sign-in produced.
  return c.json(
    {
      access_token: session.accessToken,
      refresh_token: session.refreshToken,
      expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
    },
    200,
  );
}

/**
 * `POST /v1/admin/logout` — Rust `handle_admin_logout`.
 *
 * Revocation is SERVER-SIDE and durable: the row is marked `revoked_at_unix`,
 * not deleted, so the token can never be redeemed again and the revocation
 * itself stays auditable. Deleting the row would make a replay indistinguishable
 * from a token that never existed.
 *
 * An unknown token answers `200 {revoked:false}` rather than 404 — Rust's
 * shape, and the right one: a logout endpoint that 404s on a token it does not
 * hold is a token-validity oracle for an UNAUTHENTICATED caller.
 */
async function handleLogout(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const payload = await readBody(c, refreshSchema);
  const stored = await console_.store.getRefreshTokenByHash(
    await hashRefreshToken(payload.refresh_token),
  );
  if (stored === null) return c.json({ object: "logout", revoked: false }, 200);
  if (stored.revokedAtUnix === null) {
    await console_.store.upsertRefreshToken({
      ...stored,
      revokedAtUnix: Math.floor(Date.now() / 1000),
    });
  }
  return c.json({ object: "logout", revoked: true }, 200);
}

/** `GET /v1/admin/me` — Rust `handle_admin_me`. */
async function handleMe(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  // `/me` rehydrates a persisted console session, so it passes through the SAME
  // stamped-tenant membership and Recovery lifecycle gate as every other
  // session-JWT endpoint. Decoding the token directly here is what previously
  // let a suspended tenant keep a live console session through this route.
  const { user } = await currentAdminSession(console_, bearerToken(c));
  const memberships = await console_.store.listMembershipsByUser(user.id);
  const tenantViews: Record<string, unknown>[] = [];
  for (const membership of memberships) {
    const account = await console_.deps.store.get(
      TENANT_ACCOUNTS_COLLECTION,
      PLATFORM,
      membership.tenantId,
    );
    if (account === null) continue;
    tenantViews.push({
      id: String(account.id),
      name: String(account.name ?? ""),
      // The RESOLVED tier, exactly as login/refresh do (#517). Returning the
      // raw column here would re-advertise an authority the session's key does
      // not carry: for a legacy `"superuser"` row, login answers `viewer` while
      // `/me` answered `superuser` for the very same session.
      role: membershipRoleFromStored(membership.role),
    });
  }
  return c.json({ user: userView(user), memberships: tenantViews }, 200);
}

/** `GET /v1/admin/team` — Rust `handle_admin_team_list`. Any member may read. */
async function handleTeamList(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const { membership } = await currentAdminSession(console_, bearerToken(c));
  const memberships = await console_.store.listMembershipsByTenant(membership.tenantId);
  const members: Record<string, unknown>[] = [];
  for (const member of memberships) {
    const user = await console_.store.getUserById(member.userId);
    if (user === null) continue;
    members.push({
      user_id: user.id,
      email: user.email,
      display_name: user.displayName,
      // The roster is what an owner reads before deciding whether a teammate is
      // over-privileged, so it must show the authority that teammate's session
      // actually gets.
      role: membershipRoleFromStored(member.role),
    });
  }
  return c.json({ members }, 200);
}

/** `POST /v1/admin/team/invite` — Rust `handle_admin_team_invite`. */
async function handleTeamInvite(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const { membership } = await currentAdminSession(console_, bearerToken(c));
  requireOwner(membership, "invite teammates");
  const payload = await readBody(c, inviteSchema);

  const email = payload.email.trim().toLowerCase();
  if (!isValidEmail(email)) throw unprocessable("email must be a valid address");
  // Validate the tier IN CODE, not only in the SQL CHECK: an unknown string
  // must never be stored as a role, because everything downstream (the owner
  // gate, the minted gateway scopes) then has to guess what it meant.
  const role = parseMembershipRole(payload.role.trim());
  if (role === null) {
    throw unprocessable(
      `unknown role "${payload.role.trim()}"; must be one of ${acceptedMembershipRoles()}`,
    );
  }

  const invited = await console_.store.getUserByEmail(email);
  if (invited === null) {
    throw new HttpError(
      404,
      "user_not_found",
      "no registered account with this email; ask them to register first (this creates their own tenant), then invite them again",
    );
  }
  await console_.store.upsertMembership({
    id: nextId("membership"),
    userId: invited.id,
    tenantId: membership.tenantId,
    role,
    createdAtUnix: Math.floor(Date.now() / 1000),
  });
  return c.json(
    { user_id: invited.id, email: invited.email, display_name: invited.displayName, role },
    201,
  );
}

/** `POST /v1/admin/team/members/{user_id}` — Rust `handle_admin_team_change_role`. */
async function handleTeamChangeRole(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const { membership } = await currentAdminSession(console_, bearerToken(c));
  requireOwner(membership, "change teammate roles");
  const payload = await readBody(c, changeRoleSchema);
  const targetUserId = c.req.param("user_id") ?? "";

  const role = parseMembershipRole(payload.role.trim());
  if (role === null) {
    throw unprocessable(
      `unknown role "${payload.role.trim()}"; must be one of ${acceptedMembershipRoles()}`,
    );
  }

  const existing = await console_.store.listMembershipsByTenant(membership.tenantId);
  const target = existing.find((candidate) => candidate.userId === targetUserId);
  if (target === undefined)
    throw new HttpError(404, "not_found", "no such teammate in this tenant");

  if (isOwner(membershipRoleFromStored(target.role)) && !isOwner(role)) {
    const owners = existing.filter((candidate) =>
      isOwner(membershipRoleFromStored(candidate.role)),
    ).length;
    if (owners <= 1) {
      throw new HttpError(409, "conflict", "cannot demote the last owner of a tenant");
    }
  }

  // Store the CANONICAL string, so a padded/aliased input can never reach
  // storage as a role no reader recognises.
  await console_.store.upsertMembership({ ...target, role });
  // A tier is only real if DEMOTION takes effect (#517). The tier is otherwise
  // enforced at mint time alone: an `admin` who logged in before this call
  // keeps an `admin.write` gateway key indefinitely, so writing `role` and
  // returning 200 would report a demotion that never happened. Refresh tokens
  // are deliberately left alone — the refresh path re-reads the CURRENT
  // membership and every owner-gated route re-resolves it per request, so the
  // JWT's `role` claim is not a standing grant. The gateway key IS.
  await revokeAdminConsoleSessionKeys(console_.deps, target.tenantId, targetUserId);
  return c.json({ object: "membership", user_id: targetUserId, role }, 200);
}

/** `DELETE /v1/admin/team/members/{user_id}` — Rust `handle_admin_team_revoke`. */
async function handleTeamRevoke(c: Ctx): Promise<Response> {
  const console_ = consoleOf(c);
  const { user: caller, membership } = await currentAdminSession(console_, bearerToken(c));
  requireOwner(membership, "remove teammates");
  const targetUserId = c.req.param("user_id") ?? "";

  if (caller.id === targetUserId) {
    const memberships = await console_.store.listMembershipsByTenant(membership.tenantId);
    const owners = memberships.filter((candidate) =>
      isOwner(membershipRoleFromStored(candidate.role)),
    ).length;
    if (owners <= 1) {
      // Removing the last owner would lock the tenant out of its own console.
      throw new HttpError(409, "conflict", "cannot remove the last owner of a tenant");
    }
  }

  const removed = await console_.store.deleteMembership(targetUserId, membership.tenantId);
  if (!removed) throw new HttpError(404, "not_found", "no such teammate in this tenant");
  // Removing the membership must remove the authority it granted (#517).
  // Deleting the row alone only closes the console JWT paths; the gateway
  // virtual key minted for their last session is a SEPARATE credential the
  // gateway authenticates on its own, and it would have kept working — an
  // ex-teammate holding `admin.write` on a tenant they were just removed from.
  await revokeAdminConsoleSessionKeys(console_.deps, membership.tenantId, targetUserId);
  return c.json({ object: "membership", removed: true }, 200);
}

// ---------------------------------------------------------------------------
// The mount
// ---------------------------------------------------------------------------

/** One `(method, path)` this surface owns. */
export interface AdminConsoleSessionRoute {
  readonly method: "GET" | "POST" | "DELETE";
  readonly path: string;
}

/** Every route {@link mountAdminConsoleSession} mounts, in mount order. */
export const ADMIN_CONSOLE_SESSION_ROUTES: readonly AdminConsoleSessionRoute[] = [
  { method: "POST", path: "/v1/admin/register" },
  { method: "POST", path: "/v1/admin/login" },
  { method: "POST", path: "/v1/admin/refresh" },
  { method: "POST", path: "/v1/admin/logout" },
  { method: "GET", path: "/v1/admin/me" },
  { method: "GET", path: "/v1/admin/team" },
  { method: "POST", path: "/v1/admin/team/invite" },
  { method: "POST", path: "/v1/admin/team/members/:user_id" },
  { method: "DELETE", path: "/v1/admin/team/members/:user_id" },
];

/**
 * CSRF for this surface. The SAME `adminCrossSiteRejection` `contractAuth`
 * applies to the 200 — imported, not re-implemented, so a change to the rule
 * cannot apply to one surface and not the other.
 */
async function consoleCsrf(c: Ctx, next: () => Promise<void>): Promise<void> {
  if (isStateChangingMethod(c.req.method)) {
    const deps = c.get("deps") as ControlPlaneDeps;
    const reason = adminCrossSiteRejection(c.req.raw.headers, deps.corsAllowedOrigin);
    if (reason !== null) throw new HttpError(403, "cross_site_admin_denied", reason);
  }
  await next();
}

/**
 * THE seam. Mount the nine `/v1/admin/*` console-session routes on the app.
 *
 * The composition root wires it with ONE line, after `contractAuth` and beside
 * the `/healthz` probes in `apps/control-plane/src/index.ts`:
 *
 * ```ts
 * export const MOUNTED_SESSION_ROUTES = mountAdminConsoleSession(app);
 * ```
 *
 * Returns what it actually mounted — one entry per `app.on(...)` performed —
 * so a gate can assert against what the composition root DID rather than
 * against this module's own list.
 */
export function mountAdminConsoleSession(
  app: Hono<ControlPlaneEnv>,
): readonly AdminConsoleSessionRoute[] {
  const mounted: AdminConsoleSessionRoute[] = [];
  app.use("/v1/admin/*", consoleCsrf);

  const handlers: Record<string, (c: Ctx) => Promise<Response>> = {
    "POST /v1/admin/register": handleRegister,
    "POST /v1/admin/login": handleLogin,
    "POST /v1/admin/refresh": handleRefresh,
    "POST /v1/admin/logout": handleLogout,
    "GET /v1/admin/me": handleMe,
    "GET /v1/admin/team": handleTeamList,
    "POST /v1/admin/team/invite": handleTeamInvite,
    "POST /v1/admin/team/members/:user_id": handleTeamChangeRole,
    "DELETE /v1/admin/team/members/:user_id": handleTeamRevoke,
  };

  for (const route of ADMIN_CONSOLE_SESSION_ROUTES) {
    const handler = handlers[`${route.method} ${route.path}`];
    if (handler === undefined) {
      throw new Error(`no handler for admin console route ${route.method} ${route.path}`);
    }
    app.on([route.method], route.path, handler);
    mounted.push(route);
  }
  return mounted;
}
