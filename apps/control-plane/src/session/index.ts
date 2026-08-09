/**
 * `apps/control-plane` — the admin-console SESSION surface.
 *
 * The port of `crates/ferrogate-auth-service/src/admin_console.rs` (register /
 * login / refresh / logout / me / team), which had NO TypeScript counterpart at
 * all until this module: nine routes, three durable tables that had shipped in
 * the very first control migration with neither a reader nor a writer, and the
 * whole membership-tier ladder of issue #517.
 *
 * ## THE WIRING LINE (owned by the integrate step)
 *
 * `src/index.ts` is a composition root nobody but integrate may edit, so this
 * surface is exported as a seam. To deploy it, add — after
 * `app.use("*", contractAuth())` and beside the `/healthz` probes:
 *
 * ```ts
 * import { mountAdminConsoleSession } from "./session/index.js";
 * // …
 * export const MOUNTED_SESSION_ROUTES = mountAdminConsoleSession(app);
 * ```
 *
 * and add the nine routes to `NON_CONTRACT_ROUTES` in `test/wiring.test.ts`
 * (that suite pins the exported app's Hono table to "the 214 + the four
 * probes", by exact length, so an unlisted extra mount is a deliberate RED).
 *
 * ### The mount gate
 *
 * ```ts
 * // test/wiring.test.ts, alongside the existing SELF.fetch probes
 * it("mounts the admin-console session surface on the deployed Worker", async () => {
 *   const response = await SELF.fetch(`${BASE}/v1/admin/login`, {
 *     method: "POST",
 *     headers: { "content-type": "application/json" },
 *     body: JSON.stringify({ email: "nobody@example.test", password: "x" }),
 *   });
 *   // 401/503 are the surface REFUSING; 404 `no route for` is it being absent.
 *   expect(response.status).not.toBe(404);
 * });
 * ```
 *
 * Delete the `mountAdminConsoleSession(app)` line and that assertion goes RED
 * with `404 no route for POST /v1/admin/login`, which is the property
 * `MOUNT-SEAMS.md` requires of a seam.
 *
 * ### The two bindings it needs
 *
 * | binding | where | why |
 * |---------|-------|-----|
 * | `ADMIN_CONSOLE_JWT_SECRET` | `wrangler secret put` | HS256 signing key for the session JWT. ABSENT ⇒ every route answers `503 admin_console_unconfigured`; there is deliberately no default, because a constant or per-isolate fallback is worse than being down. |
 * | `DB` | already bound | `admin_users`, `admin_user_tenant_memberships`, `admin_user_refresh_tokens`. |
 *
 * Both are checked per request and refuse LOUDLY, so a deployment that mounts
 * the routes without provisioning the secret cannot silently issue forgeable
 * sessions.
 */
export {
  ADMIN_CONSOLE_JWT_SECRET_BINDING,
  ADMIN_CONSOLE_SESSION_ROUTES,
  type AdminConsoleSessionRoute,
  mountAdminConsoleSession,
} from "./routes.js";
export {
  ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
  ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
  type AdminSessionClaims,
  signAdminAccessToken,
  verifyAdminAccessToken,
} from "./tokens.js";
export {
  MEMBERSHIP_ROLES,
  type MembershipRole,
  acceptedMembershipRoles,
  gatewayApiKeyScopes,
  isOwner,
  membershipRoleFromStored,
  parseMembershipRole,
} from "./membership_role.js";
export {
  PBKDF2_ITERATIONS,
  constantTimeEqual,
  generateRefreshTokenSecret,
  hashPassword,
  isValidEmail,
  nextId,
  slugifyWithSuffix,
  unusablePasswordHash,
  verifyPassword,
} from "./credentials.js";
export {
  ADMIN_CONSOLE_SESSION_KEY_NAME,
  VIRTUAL_KEYS_COLLECTION,
  provisionGatewayApiKey,
  requireUsableConsoleTenancy,
  revokeAdminConsoleSessionKeys,
} from "./gateway_key.js";
export {
  platformOperatorApiKeyId,
  provisionPlatformOperatorApiKey,
  revokePlatformOperatorApiKey,
} from "./operator_key.js";
export {
  type AdminConsoleSessionStore,
  type AdminMembershipRow,
  type AdminRefreshTokenRow,
  type AdminUserRow,
  D1AdminConsoleSessionStore,
} from "./store.js";
