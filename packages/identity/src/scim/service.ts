/**
 * SCIM 2.0 user/group provisioning.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/scim.rs`
 * (issues #161 / #232 / #492 / #517).
 *
 * INVARIANT for every function below: `tenantId` comes from
 * `resolveScimTenant` and from nowhere else. No handler reads a tenant from a
 * path, a query or a body, and no read or write is issued without it. That is
 * why a SCIM token cannot reach outside its tenant — not because each handler
 * remembers to check, but because there is no other tenant available to it.
 */
import { forbidden, internalError, lifecycleError, scimError, storageError } from "../errors.js";
import { isOwnerRole, membershipRoleFromStored, parseMembershipRole } from "../membership-role.js";
import type {
  AdminSessionPort,
  ApiKeyAuthenticatorPort,
  IdentityClock,
  IdentityRandom,
  IdentityRepository,
  IdentityResponse,
  StoredAdminUser,
} from "../ports.js";
import { UNUSABLE_PASSWORD_HASH, isValidEmail, nextId } from "../util.js";
import { SCIM_PROVISION_SCOPE } from "./auth.js";
import { matchesScimFilter, parseScimFilter } from "./filter.js";
import {
  SCIM_GROUP_SCHEMA,
  type ScimUserResource,
  scimListResponse,
  scimUserResource,
  scimUserResourceWithActive,
} from "./resources.js";

export interface ScimDeps {
  repository: IdentityRepository;
  apiKeys: ApiKeyAuthenticatorPort;
  clock: IdentityClock;
  random: IdentityRandom;
  session: AdminSessionPort;
}

export interface ScimListOptions {
  filter?: string | null;
  /** 1-based, per RFC 7644 §3.4.2.4. */
  startIndex?: number | null;
  count?: number | null;
}

export interface ScimUserRequest {
  userName?: unknown;
  active?: unknown;
  displayName?: unknown;
  /**
   * FerroGate extension outside the core User schema: the tenant tier to
   * assign. Defaults to `member`.
   */
  ferrogateRole?: unknown;
}

/** The tenant role a user's membership row carries here, or `null`. */
async function membershipRoleInTenant(
  repository: IdentityRepository,
  tenantId: string,
  userId: string,
): Promise<string | null> {
  const memberships = await repository.listAdminUserMembershipsByTenant(tenantId);
  return memberships.find((membership) => membership.userId === userId)?.role ?? null;
}

/**
 * Applies `?filter=`, then `startIndex`/`count`. Returns the SCIM 400 when the
 * filter does not parse — never an unfiltered listing.
 */
function paginate(
  resources: Record<string, unknown>[],
  options: ScimListOptions,
): IdentityResponse {
  let matched = resources;
  if (options.filter !== undefined && options.filter !== null && options.filter !== "") {
    const parsed = parseScimFilter(options.filter);
    if (!parsed.ok) {
      return scimError(400, `could not parse the filter: ${parsed.reason}`, "invalidFilter");
    }
    matched = resources.filter((resource) => matchesScimFilter(parsed.filter, resource));
  }
  const total = matched.length;
  const startIndex = Math.max(1, Math.trunc(options.startIndex ?? 1));
  const count =
    options.count === undefined || options.count === null
      ? matched.length
      : Math.max(0, Math.trunc(options.count));
  const page = matched.slice(startIndex - 1, startIndex - 1 + count);
  return { status: 200, scim: true, body: scimListResponse(page, total, startIndex) };
}

/** `GET /scim/v2/Users` — this tenant's members, and only this tenant's. */
export async function scimUsersList(
  deps: ScimDeps,
  tenantId: string,
  options: ScimListOptions,
): Promise<IdentityResponse> {
  let resources: ScimUserResource[];
  try {
    const memberships = await deps.repository.listAdminUserMembershipsByTenant(tenantId);
    resources = [];
    for (const membership of memberships) {
      const user = await deps.repository.getAdminUserById(membership.userId);
      // A membership row pointing at a deleted account is skipped, not
      // surfaced as a half-populated resource.
      if (user) resources.push(scimUserResource(user, membership.role));
    }
  } catch (error) {
    return storageError(error);
  }
  return paginate(resources, options);
}

/** `GET /scim/v2/Users/{id}`. */
export async function scimUserGet(
  deps: ScimDeps,
  tenantId: string,
  userId: string,
): Promise<IdentityResponse> {
  try {
    const role = await membershipRoleInTenant(deps.repository, tenantId, userId);
    // A user that exists but belongs to ANOTHER tenant is a 404 here, with a
    // message that does not distinguish it from a nonexistent id — the
    // difference is exactly the cross-tenant existence oracle.
    if (role === null) return scimError(404, "no such user in this tenant");
    const user = await deps.repository.getAdminUserById(userId);
    if (!user) return scimError(404, "no such user");
    return { status: 200, scim: true, body: scimUserResource(user, role) };
  } catch (error) {
    return storageError(error);
  }
}

/**
 * `POST /scim/v2/Users`.
 *
 * Creates a user under the token's tenant, or — when an account with this
 * address already exists — adds a membership for it. NEVER creates a tenant,
 * project or workspace, and never touches the account's OTHER memberships.
 */
export async function scimUserCreate(
  deps: ScimDeps,
  tenantId: string,
  payload: ScimUserRequest,
): Promise<IdentityResponse> {
  const email = typeof payload.userName === "string" ? payload.userName.trim().toLowerCase() : "";
  if (!isValidEmail(email)) {
    return scimError(422, "userName must be a valid email address", "invalidValue");
  }
  // #517: SCIM writes this straight into `admin_user_tenant_memberships.role`,
  // and the D1 backend carries no CHECK to catch an unknown value. Validated
  // BEFORE anything is written, so a bad request leaves no partial account.
  const requestedRole =
    typeof payload.ferrogateRole === "string" && payload.ferrogateRole.trim().length > 0
      ? payload.ferrogateRole.trim()
      : "member";
  const role = parseMembershipRole(requestedRole);
  if (!role) {
    return scimError(
      422,
      `ferrogateRole: unknown role ${JSON.stringify(requestedRole)}`,
      "invalidValue",
    );
  }
  const displayName =
    typeof payload.displayName === "string" && payload.displayName.trim().length > 0
      ? payload.displayName.trim()
      : email;

  let user: StoredAdminUser;
  try {
    const existing = await deps.repository.getAdminUserByEmail(email);
    if (existing) {
      user = existing;
    } else {
      const now = deps.clock.nowUnix();
      user = {
        id: nextId("user", deps.random),
        email,
        passwordHash: UNUSABLE_PASSWORD_HASH,
        displayName,
        superadmin: false,
        createdAtUnix: now,
        updatedAtUnix: now,
        lastLoginAtUnix: null,
        disabledAtUnix: null,
      };
      await deps.repository.upsertAdminUser(user);
    }
    await deps.repository.upsertAdminUserMembership({
      id: nextId("membership", deps.random),
      userId: user.id,
      tenantId,
      role,
      createdAtUnix: deps.clock.nowUnix(),
    });
  } catch (error) {
    return storageError(error);
  }

  if (payload.active === false) {
    const deactivated = await deactivateAdminUserInTenant(deps, tenantId, user.id);
    if (deactivated) return deactivated;
  }
  return {
    status: 201,
    scim: true,
    body: scimUserResourceWithActive(user, role, payload.active !== false),
  };
}

/**
 * Tenant-scoped deprovisioning (issue #232).
 *
 * SCIM auth is per-tenant, so deactivation must be too:
 *  - revoke only THIS tenant's refresh tokens, and this tenant's console
 *    gateway keys (#517 — revoking tokens alone leaves a deprovisioned user
 *    holding a live `admin.write` Admin API credential the gateway
 *    authenticates on its own);
 *  - remove only this tenant's membership when the user belongs to others —
 *    before this, any tenant owner could disable a shared account system-wide
 *    just by knowing its address;
 *  - only when this was the LAST membership, disable the global account and
 *    revoke every remaining token. The membership row is KEPT in that case, so
 *    a later `active: true` from the same tenant can reactivate them.
 *
 * Returns a refusal response, or `null` on success.
 */
async function deactivateAdminUserInTenant(
  deps: ScimDeps,
  tenantId: string,
  userId: string,
): Promise<IdentityResponse | null> {
  try {
    const user = await deps.repository.getAdminUserById(userId);
    if (!user) return scimError(404, "no such user");
    const now = deps.clock.nowUnix();
    await deps.repository.revokeAdminUserRefreshTokensForTenant(userId, tenantId, now);
    await deps.repository.revokeAdminConsoleSessionKeys(tenantId, userId);

    const memberships = await deps.repository.listAdminUserMembershipsByUser(userId);
    const hasOtherMemberships = memberships.some((membership) => membership.tenantId !== tenantId);
    if (hasOtherMemberships) {
      await deps.repository.deleteAdminUserMembership(userId, tenantId);
      return null;
    }
    await deps.repository.upsertAdminUser({ ...user, disabledAtUnix: now });
    await deps.repository.revokeAllAdminUserRefreshTokens(userId, now);
    return null;
  } catch (error) {
    return storageError(error);
  }
}

async function reactivateAdminUser(
  deps: ScimDeps,
  userId: string,
): Promise<IdentityResponse | null> {
  try {
    const user = await deps.repository.getAdminUserById(userId);
    if (!user) return scimError(404, "no such user");
    await deps.repository.upsertAdminUser({ ...user, disabledAtUnix: null });
    return null;
  } catch (error) {
    return storageError(error);
  }
}

/**
 * Reads `active` out of either a simplified `{"active": false}` body or a
 * standards-shaped PATCH
 * `{"Operations":[{"op":"replace","path":"active","value":false}]}`.
 * `undefined` when neither is determinable — which the caller turns into a
 * 422 rather than guessing at a default.
 */
export function parseScimActivePatch(body: unknown): boolean | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;
  if (typeof record.active === "boolean") return record.active;
  const operations = record.Operations ?? record.operations;
  if (!Array.isArray(operations)) return undefined;
  for (const operation of operations) {
    if (typeof operation !== "object" || operation === null) continue;
    const entry = operation as Record<string, unknown>;
    const path = entry.path;
    if (typeof path !== "string" || path.toLowerCase() !== "active") continue;
    if (typeof entry.value === "boolean") return entry.value;
    // Some IdPs send `{"op":"replace","path":"active","value":{"active":false}}`
    if (typeof entry.value === "object" && entry.value !== null) {
      const nested = (entry.value as Record<string, unknown>).active;
      if (typeof nested === "boolean") return nested;
    }
  }
  return undefined;
}

/** `PATCH` / `PUT` `/scim/v2/Users/{id}` — the `active` lifecycle. */
export async function scimUserPatch(
  deps: ScimDeps,
  tenantId: string,
  userId: string,
  body: unknown,
): Promise<IdentityResponse> {
  let role: string | null;
  try {
    role = await membershipRoleInTenant(deps.repository, tenantId, userId);
  } catch (error) {
    return storageError(error);
  }
  if (role === null) return scimError(404, "no such user in this tenant");

  const active = parseScimActivePatch(body);
  if (active === undefined) {
    return scimError(422, "could not determine an 'active' value from the PATCH body");
  }
  const failure = active
    ? await reactivateAdminUser(deps, userId)
    : await deactivateAdminUserInTenant(deps, tenantId, userId);
  if (failure) return failure;

  try {
    const user = await deps.repository.getAdminUserById(userId);
    if (!user) return scimError(404, "no such user");
    return {
      status: 200,
      scim: true,
      body: scimUserResourceWithActive(user, role, active && user.disabledAtUnix === null),
    };
  } catch (error) {
    return storageError(error);
  }
}

/** `DELETE /scim/v2/Users/{id}` — deprovision from THIS tenant. */
export async function scimUserDelete(
  deps: ScimDeps,
  tenantId: string,
  userId: string,
): Promise<IdentityResponse> {
  let role: string | null;
  try {
    role = await membershipRoleInTenant(deps.repository, tenantId, userId);
  } catch (error) {
    return storageError(error);
  }
  // The membership check comes FIRST and nothing is revoked before it passes:
  // a DELETE aimed at another tenant's user must have no side effect at all.
  if (role === null) return scimError(404, "no such user in this tenant");
  const failure = await deactivateAdminUserInTenant(deps, tenantId, userId);
  if (failure) return failure;
  return { status: 204, scim: true, body: null };
}

/**
 * `GET /scim/v2/Groups` — the tenant's in-use tiers, as a read-only view.
 *
 * Resolved tiers, not raw columns (#517): a group here is a role an IdP may
 * push users into, so advertising a legacy `"superuser"` row as a group would
 * offer an assignable tier that the create path rejects on the way back in.
 */
export async function scimGroupsList(
  deps: ScimDeps,
  tenantId: string,
  options: ScimListOptions,
): Promise<IdentityResponse> {
  let roles: string[];
  try {
    const memberships = await deps.repository.listAdminUserMembershipsByTenant(tenantId);
    roles = [...new Set(memberships.map((m) => membershipRoleFromStored(m.role)))].sort();
  } catch (error) {
    return storageError(error);
  }
  const resources = roles.map((role) => ({
    schemas: [SCIM_GROUP_SCHEMA],
    id: role,
    displayName: role,
    meta: { resourceType: "Group" },
  }));
  return paginate(resources, options);
}

/**
 * `POST /v1/admin/team/scim-token` — mints a SCIM provisioning credential for
 * the caller's own tenant.
 *
 * The token is an ordinary virtual API key carrying ONLY
 * `scim.provision`, so it is revoked/rotated through the same
 * `/admin/v1/virtual-keys` endpoints as any other key. The plaintext secret is
 * returned exactly once and never persisted (#492) — storage keeps the hash.
 */
export async function mintScimToken(
  deps: ScimDeps,
  sessionToken: string | null,
): Promise<IdentityResponse> {
  if (!sessionToken)
    return {
      status: 401,
      body: { error: { type: "unauthorized", message: "missing bearer token" } },
    };
  let current: Awaited<ReturnType<AdminSessionPort["currentAdminSession"]>>;
  try {
    current = await deps.session.currentAdminSession(sessionToken);
  } catch {
    current = null;
  }
  if (!current) {
    return { status: 401, body: { error: { type: "unauthorized", message: "invalid session" } } };
  }
  if (!isOwnerRole(membershipRoleFromStored(current.membership.role))) {
    return forbidden("only a tenant owner can create a SCIM provisioning token");
  }
  const tenantId = current.membership.tenantId;

  let workspace: Awaited<ReturnType<IdentityRepository["resolveDefaultWorkspace"]>>;
  try {
    workspace = await deps.repository.resolveDefaultWorkspace(tenantId);
  } catch (error) {
    return storageError(error);
  }
  if (!workspace) return internalError("no workspace found for this tenant");

  // A disabled tenancy may keep an admin-console RECOVERY session, but that
  // carve-out must not mint a new long-lived provisioning credential. The full
  // workspace chain is checked BEFORE any secret material is generated.
  try {
    await deps.repository.requireUsableTenancy("attach", {
      tenantId: workspace.tenantId,
      projectId: workspace.projectId,
      workspaceId: workspace.id,
    });
  } catch (error) {
    return lifecycleError(error);
  }

  try {
    const material = await deps.session.mintVirtualApiKeySecret();
    const now = deps.clock.nowUnix();
    await deps.repository.upsertApiKeyRecord({
      id: nextId("scim", deps.random),
      tenantId,
      projectId: workspace.projectId,
      workspaceId: workspace.id,
      name: "SCIM provisioning token",
      keyPrefix: material.keyPrefix,
      keyHash: material.keyHash,
      last4: material.last4,
      enabled: true,
      scopes: [SCIM_PROVISION_SCOPE],
      createdAtUnix: now,
      updatedAtUnix: now,
    });
    return { status: 201, body: { token: material.secret } };
  } catch (error) {
    return storageError(error);
  }
}
