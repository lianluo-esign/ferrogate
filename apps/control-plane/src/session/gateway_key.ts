/**
 * The console session's GATEWAY credential — mint, and the revocation sweep
 * that makes the tier ladder retroactive.
 *
 * Port of `admin_console.rs`'s `provision_gateway_api_key` +
 * `revoke_admin_console_session_keys` (issues #157, #514, #517).
 *
 * Register / login answer with a freshly minted `fg_...` virtual key so the
 * console can immediately drive the gateway's own Admin API. It is an ORDINARY
 * virtual key — the same document `POST /admin/v1/virtual-keys` writes and the
 * same two credential rows `store/virtual_keys.ts` projects — with two things
 * that make it findable again:
 *
 *  - `name` is exactly {@link ADMIN_CONSOLE_SESSION_KEY_NAME}. That string is
 *    the ONLY marker distinguishing a session key from a virtual key an
 *    operator deliberately created, so the sweeps below key off it and it must
 *    never widen;
 *  - `user_id` attributes it to the admin user, so a sweep can revoke ONE
 *    person's session keys without collateral damage to their teammates'.
 *
 * ## Minting REVOKES first — that is what makes a demotion mean anything
 *
 * Deriving the scopes from the caller's tier only fixes the NEXT key. A key
 * already in a browser's hands keeps whatever it was minted with, forever:
 * the document carries no expiry. So every mint sweeps the caller's prior
 * session keys for that tenant, and so do
 * `handle_admin_team_change_role`'s and `handle_admin_team_revoke`'s callers.
 * Without that, an `admin` demoted to `viewer` keeps `admin.write` until
 * somebody finds the key by hand.
 *
 * ## The lifecycle gate is `Recovery`, not `Request`
 *
 * This function MINTS a live credential, so #514 gates it — but on the Recovery
 * seam: `disabled` is the tenant's OWN off switch, and refusing to mint a
 * console session under a disabled project would lock the tenant out of the
 * console it needs to re-enable it. `suspended`/`deleted` deny, because those
 * are platform actions an operator reverses with an operator key that carries
 * no tenancy chain.
 *
 * The refusal is a **403 with the gateway's own code**, never a 500 and —
 * the part that matters — never a live `fg_...` secret. Rust names this as the
 * exact probe row #514 enumerates: before the gate became reachable from
 * `ferrogate-auth-service`, `POST /v1/admin/login` against a suspended tenant
 * still returned a working gateway key.
 */
import type { ApiOperation } from "../contract.js";
import { HttpError } from "../middleware/errors.js";
import type { AuthContext, ControlPlaneDeps, ListQuery, StoreRecord, Tenancy } from "../ports.js";
import { RECOVERY_OPERATION_IDS } from "../store/lifecycle.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import { projectVirtualKey, virtualKeyProjectable } from "../store/virtual_keys.js";
import { nextId } from "./credentials.js";
import { type MembershipRole, gatewayApiKeyScopes } from "./membership_role.js";

/** The document collection `routes/admin_virtual_key.ts` owns. */
export const VIRTUAL_KEYS_COLLECTION = "virtual-keys";

/**
 * Rust `ADMIN_CONSOLE_SESSION_KEY_NAME`. The marker the sweeps key off.
 * **Must never widen** — an operator's own virtual key is not a session
 * artifact and must survive every sweep below.
 */
export const ADMIN_CONSOLE_SESSION_KEY_NAME = "Admin console session";

/** Rust `api_key.rs`: `fg_<hex>`. Same shape `admin_virtual_key.ts` mints. */
const SECRET_PREFIX = "fg_";

/**
 * The console session gateway key expires in lockstep with the browser session
 * cookie (vega `SESSION_TTL_SEC`). Both are 400 days — the browser's Max-Age /
 * Expires ceiling — so an idle session's cookie and its gateway key lapse at the
 * same wall-clock time, while an active session re-mints BOTH on every login.
 * This ties the two lifetimes together: once the cookie is gone the key is
 * already dead, so a lifted cookie cannot outlive the session it was minted for.
 * The projection carries this to every resolve surface (`api_keys.expires_at_unix`,
 * `api_key_directory`, and the KV row) via `projectVirtualKey`; the gateway then
 * fails an expired key closed with a 401 (`key_suspended`, reason `expired`).
 */
const CONSOLE_SESSION_KEY_TTL_SECS = 400 * 24 * 60 * 60;

/**
 * The Recovery-seam probe the lifecycle gate is asked with.
 *
 * `TenancyLifecycleGatePort.admit` is operation-shaped because the 211
 * contract routes are, and the seam a request is decided on IS the operation's
 * identity (`RECOVERY_OPERATION_IDS` in `store/lifecycle.ts`). The console's
 * session endpoints are Rust `LifecycleSeam::Recovery`, so they borrow a
 * recovery operation's identity rather than growing a second gate with its own
 * copy of the `disabled`-is-reversible rule — two implementations of one
 * predicate is precisely how a gate ends up enforced on one path and not the
 * other.
 */
const CONSOLE_RECOVERY_OPERATION: ApiOperation = {
  path: "/admin/v1/tenant-accounts/{tenant_id}",
  honoPath: "/admin/v1/tenant-accounts/:tenant_id",
  method: "PATCH",
  operationId: "updateTenantAccount",
  visibility: "admin",
  auth: { kind: "bearer", scope: "admin.write", scopeDiscriminator: null },
  rbacAction: null,
  group: "tenant_hierarchy",
};

if (!RECOVERY_OPERATION_IDS.has(CONSOLE_RECOVERY_OPERATION.operationId)) {
  // A rename in `store/lifecycle.ts` would silently turn the console's gate
  // into the stricter Request seam and lock every `disabled` tenant out of the
  // console it needs to re-enable itself. Fail at module load instead.
  throw new Error(
    `${CONSOLE_RECOVERY_OPERATION.operationId} is no longer a recovery operation; the admin-console session gate would change seam`,
  );
}

/** The synthetic caller the lifecycle gate resolves the chain for. */
function gateAuth(tenancy: Tenancy): AuthContext {
  return {
    subject: tenancy.userId ?? null,
    tenancy,
    // No scopes: the gate reads the chain, never the caller's authority.
    scopes: [],
    platformOperator: false,
    source: "durable_native",
  };
}

/**
 * Refuse a suspended/deleted tenancy the same way the gateway does.
 * Throws `HttpError`; returns normally when the chain admits.
 */
export async function requireUsableConsoleTenancy(
  deps: ControlPlaneDeps,
  tenancy: Tenancy,
): Promise<void> {
  const decision = await deps.lifecycle.admit(gateAuth(tenancy), CONSOLE_RECOVERY_OPERATION);
  if (decision.admitted === "unavailable") {
    // Never an implicit allow. Rust `LifecycleGateError::Unavailable` → 503.
    throw new HttpError(
      503,
      "lifecycle_status_unavailable",
      `failed to resolve tenancy lifecycle: ${decision.detail}`,
    );
  }
  if (decision.admitted !== true) {
    throw new HttpError(403, decision.code, decision.message);
  }
}

function mintSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return `${SECRET_PREFIX}${hex}`;
}

async function hashSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

const LIST_EVERYTHING: ListQuery = {
  offset: 0,
  limit: 1000,
  paginate: false,
  search: null,
  filters: {},
};

/** Project a virtual-key document into the credential rows, when both databases exist. */
async function project(
  deps: ControlPlaneDeps,
  record: StoreRecord,
  direction: "loosen" | "tighten",
): Promise<void> {
  const controlDb = deps.controlDatabase;
  if (controlDb === null) return;
  if (!virtualKeyProjectable(record)) return;
  const tenantId = typeof record.tenant_id === "string" ? record.tenant_id : null;
  const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);
  if (handle === null) return;
  await projectVirtualKey(
    controlDb,
    handle,
    record,
    Math.floor(Date.now() / 1000),
    direction,
    deps.keyDirectory,
  );
}

/**
 * Revoke the console-session gateway keys ONE user holds in ONE tenant.
 * Rust `revoke_admin_console_session_keys`. Returns how many were revoked.
 *
 * Two populations are swept, and the distinction is deliberate:
 *
 *  - **attributed** keys (`user_id === adminUserId`) — minted by this code.
 *    Precise: no other user is touched.
 *  - **unattributed** keys (`user_id` absent) — rows from before the mint
 *    stamped an owner. They cannot be attributed to a user at all, and they are
 *    exactly the over-scoped population, so they are swept tenant-wide. The
 *    cost is one forced re-login for other console users of that tenant; the
 *    sweep is self-extinguishing, since every key minted from here on carries a
 *    `user_id` and only ever matches its own owner.
 *
 * Deliberately does NOT touch a key with any other `name`.
 */
export async function revokeAdminConsoleSessionKeys(
  deps: ControlPlaneDeps,
  tenantId: string,
  adminUserId: string,
  opts?: { readonly exceptKeyId?: string },
): Promise<number> {
  const scope = { kind: "tenant", tenantId } as const;
  const page = await deps.store.list(VIRTUAL_KEYS_COLLECTION, scope, LIST_EVERYTHING);
  const now = Math.floor(Date.now() / 1000);
  let revoked = 0;
  for (const record of page.items) {
    if (record.name !== ADMIN_CONSOLE_SESSION_KEY_NAME) continue;
    // Spare the freshly-minted key when the sweep runs AFTER the mint (deferred
    // login path). It carries the same name + user_id, so without this guard the
    // sweep would revoke the very key just handed to the client. Covers both the
    // attributed and unattributed-legacy branches below.
    if (opts?.exceptKeyId !== undefined && String(record.id) === opts.exceptKeyId) continue;
    // Already fully revoked — Rust skips a row that is both revoked and
    // disabled so a repeat sweep is free.
    if (record.revoked === true && record.enabled === false) continue;
    const owner =
      typeof record.user_id === "string" && record.user_id !== "" ? record.user_id : null;
    const belongsToCaller = owner === adminUserId;
    const unattributedLegacy = owner === null;
    if (!belongsToCaller && !unattributedLegacy) continue;

    const merged = await deps.store.merge(VIRTUAL_KEYS_COLLECTION, scope, String(record.id), {
      enabled: false,
      revoked: true,
      revoked_at: now,
    });
    if (merged === null) continue;
    // TIGHTEN: the directory leg goes first, so a crash between the two legs
    // has ALREADY stopped the credential resolving.
    await project(deps, merged, "tighten");
    revoked += 1;
  }
  return revoked;
}

/** Where the minted key is scoped, and who it is attributed to. */
export interface ConsoleKeyMintRequest {
  readonly tenantId: string;
  readonly projectId: string;
  readonly workspaceId: string;
  readonly adminUserId: string;
  readonly role: MembershipRole;
}

/**
 * Mint the console session's gateway virtual key. Rust
 * `provision_gateway_api_key`.
 *
 * Order, and every step is load-bearing:
 *  1. the #514 Recovery lifecycle gate — a suspended tenancy gets a 403 and no
 *     secret at all;
 *  2. the #517 sweep — the caller's prior session keys for this tenant stop
 *     resolving BEFORE a new one exists, so there is no window in which two of
 *     them work;
 *  3. the document, then the credential rows in the LOOSEN order (tenant row
 *     first), so a crash leaves a key that cannot yet authenticate.
 *
 * Returns the plaintext secret (shown once, never recoverable, exactly like
 * `POST /admin/v1/virtual-keys`) AND the new key's id, so a caller that defers
 * the sweep can pass it as `exceptKeyId` to avoid revoking this very key.
 *
 * `opts.skipRevokeSweep` lets the login path move step 2 (the prior-session
 * sweep) OFF the synchronous response path onto `ctx.waitUntil`; the caller
 * MUST then run the sweep itself with `{ exceptKeyId }` set to the returned id.
 */
export async function provisionGatewayApiKey(
  deps: ControlPlaneDeps,
  request: ConsoleKeyMintRequest,
  opts?: { readonly skipRevokeSweep?: boolean },
): Promise<{ secret: string; keyId: string }> {
  await requireUsableConsoleTenancy(deps, {
    tenantId: request.tenantId,
    projectId: request.projectId,
    workspaceId: request.workspaceId,
    userId: request.adminUserId,
  });

  if (opts?.skipRevokeSweep !== true) {
    await revokeAdminConsoleSessionKeys(deps, request.tenantId, request.adminUserId);
  }

  const secret = mintSecret();
  const now = Math.floor(Date.now() / 1000);
  const record: StoreRecord = {
    id: nextId("vk"),
    name: ADMIN_CONSOLE_SESSION_KEY_NAME,
    tenant_id: request.tenantId,
    project_id: request.projectId,
    workspace_id: request.workspaceId,
    // Attribution, so a later sweep can revoke THIS user's session keys
    // without collateral damage to their teammates'.
    user_id: request.adminUserId,
    key_hash: await hashSecret(secret),
    key_prefix: secret.slice(0, 16),
    last4: secret.slice(-4),
    enabled: true,
    revoked: false,
    scopes: [...gatewayApiKeyScopes(request.role)],
    allowed_models: [],
    allowed_providers: [],
    created_at: now,
    // Expire in lockstep with the browser session cookie (see
    // CONSOLE_SESSION_KEY_TTL_SECS). `projectVirtualKey` reads `expires_at` and
    // stamps `expires_at_unix` onto every credential row the gateway resolves.
    expires_at: now + CONSOLE_SESSION_KEY_TTL_SECS,
  };

  const stored = await deps.store.create(
    VIRTUAL_KEYS_COLLECTION,
    { kind: "tenant", tenantId: request.tenantId },
    record,
  );
  await project(deps, stored, "loosen");
  return { secret, keyId: String(stored.id) };
}
