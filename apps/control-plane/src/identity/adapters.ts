/**
 * THE COMPOSITION ROOT for the enterprise-identity surfaces.
 *
 * `packages/identity` (OIDC + SCIM) and `packages/sso` (SAML) deliberately own
 * no persistence: every store is an interface, so each authorization predicate
 * has exactly ONE implementation and cannot be re-decided per protocol. This
 * file is where those interfaces meet D1, the console session machinery and the
 * virtual-key credential path this Worker already owns.
 *
 * It is the integrate step's file (a package may not edit an app's `src`), and
 * it re-uses rather than re-implements:
 *
 * | seam | reused from |
 * |---|---|
 * | admin users / memberships / refresh tokens | `session/store.ts` (`D1AdminConsoleSessionStore`) |
 * | the console session JWT | `session/tokens.ts` |
 * | the tier-scoped gateway key mint (#514/#517) | `session/gateway_key.ts` |
 * | the virtual-key credential projection | `store/virtual_keys.ts` |
 * | the tenancy lifecycle gate | `deps.lifecycle` |
 * | `env://` secret references | `@ferrogate/secrets` |
 *
 * The one thing implemented HERE rather than reused is the SSO tables
 * (`sso_provider_configs`, `sso_pending_flows`), because nothing else in this
 * Worker reads them — and `takeSsoPendingFlow` is a single
 * `DELETE … RETURNING` statement on purpose: a `SELECT` then a `DELETE`
 * reintroduces the replay both protocols rely on it to stop.
 */
import type {
  AdminSessionPort,
  ApiKeyDecision,
  ApiKeyAuthenticatorPort as IdentityApiKeyAuthenticatorPort,
  IdentityClock,
  IdentityDeps,
  IdentityRandom,
  IdentityRepository,
  LifecycleSeam,
  SecretResolverPort,
  StoredAdminUser,
  StoredAdminUserMembership,
  StoredApiKeyRecord,
  StoredSsoPendingFlow,
  StoredSsoProviderConfig,
  StoredTenantAccount,
  StoredWorkspaceRef,
  TenancyRefs,
} from "@ferrogate/identity";
import { JwksCache } from "@ferrogate/identity";
import type { EnvLike } from "@ferrogate/secrets";
import { EnvSecretResolver, parseSecretRef } from "@ferrogate/secrets";
import { StorageError, backfillTenantConfigurationPolicy } from "@ferrogate/storage";
import type {
  SamlPorts,
  StoredSsoProviderConfig as SamlStoredSsoProviderConfig,
  SsoPendingFlow,
} from "@ferrogate/sso";
import { webCryptoRandomHex } from "@ferrogate/sso";
import type { Context } from "hono";
import type { ApiOperation } from "../contract.js";
import { HttpError } from "../middleware/errors.js";
import type {
  AuthContext,
  ControlPlaneDeps,
  ControlPlaneEnv,
  ListQuery,
  StoreRecord,
  Tenancy,
} from "../ports.js";
import { generateRandomHex, nextId } from "../session/credentials.js";
import {
  VIRTUAL_KEYS_COLLECTION,
  provisionGatewayApiKey,
  revokeAdminConsoleSessionKeys,
} from "../session/gateway_key.js";
import { membershipRoleFromStored } from "../session/membership_role.js";
import { ADMIN_CONSOLE_JWT_SECRET_BINDING } from "../session/routes.js";
import { D1AdminConsoleSessionStore } from "../session/store.js";
import {
  ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
  ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
  signAdminAccessToken,
  verifyAdminAccessToken,
} from "../session/tokens.js";
import {
  PROJECTS_COLLECTION,
  RECOVERY_OPERATION_IDS,
  TENANT_ACCOUNTS_COLLECTION,
  WORKSPACES_COLLECTION,
} from "../store/lifecycle.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import { projectVirtualKey, virtualKeyProjectable } from "../store/virtual_keys.js";

// ---------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------

const LIST_EVERYTHING: ListQuery = {
  offset: 0,
  limit: 1000,
  paginate: false,
  search: null,
  filters: {},
};

/** One clock for the whole request family. Unix seconds, like the Rust port. */
export const identityClock: IdentityClock = {
  nowUnix: () => Math.floor(Date.now() / 1000),
};

/** CSPRNG hex, the same construction `session/credentials.ts` uses. */
export const identityRandom: IdentityRandom = {
  hex: (byteLength: number) => generateRandomHex(byteLength),
};

/**
 * The JWKS cache is per-ISOLATE, not per-request.
 *
 * Rebuilding it inside `resolveIdentityDeps` would make the cache useless — a
 * fresh instance per request re-fetches the IdP's key set on EVERY callback,
 * which is both a latency cost and a way to get rate-limited by the IdP at
 * exactly the moment logins are happening. The cache's own TTL and forced
 * refresh cooldown are what bound staleness; see `oidc/jwks.ts`.
 */
let sharedJwks: JwksCache | null = null;
function jwksCache(): JwksCache {
  if (sharedJwks === null) {
    sharedJwks = new JwksCache({
      fetch: (url, init) => fetch(url, init),
      clock: identityClock,
    });
  }
  return sharedJwks;
}

/** Test seam: drop the per-isolate JWKS cache so a suite starts clean. */
export function resetIdentityJwksCache(): void {
  sharedJwks = null;
}

/**
 * The console signing secret, or `null`.
 *
 * `null` is NOT a degraded mode: every caller turns it into a refusal. There is
 * deliberately no constant and no per-isolate fallback — the first is forgeable
 * by anyone who reads the source, the second silently invalidates every session
 * on isolate eviction. Same rule as `session/routes.ts`'s `consoleOf`.
 */
export function adminConsoleJwtSecret(env: unknown): string | null {
  const raw = (env as Record<string, unknown> | null | undefined)?.[
    ADMIN_CONSOLE_JWT_SECRET_BINDING
  ];
  const secret = typeof raw === "string" ? raw.trim() : "";
  return secret === "" ? null : secret;
}

/** Rust `hash_virtual_api_key_secret` — the construction every FerroGate hash uses. */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.trim()));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

/**
 * The lifecycle operation each identity seam is gated on.
 *
 * `"request"` is the STRICT seam (a suspended *or* disabled tenancy refuses);
 * `"attach"` uses the same strict seam because minting a long-lived SCIM
 * provisioning credential is not a recovery action. The console's own
 * `Recovery` carve-out (`session/gateway_key.ts`) deliberately does NOT apply
 * here: a disabled tenant may still reach the console to re-enable itself, but
 * it may not hand a third-party IdP a directory-administration token while
 * disabled.
 */
const IDENTITY_REQUEST_OPERATION: ApiOperation = {
  path: "/admin/v1/virtual-keys",
  honoPath: "/admin/v1/virtual-keys",
  method: "POST",
  operationId: "createVirtualKey",
  visibility: "admin",
  auth: { kind: "bearer", scope: "admin.write", scopeDiscriminator: null },
  rbacAction: null,
  group: "virtual_keys",
};

if (RECOVERY_OPERATION_IDS.has(IDENTITY_REQUEST_OPERATION.operationId)) {
  // If this ever became a recovery operation the SCIM-token mint would start
  // admitting a disabled tenancy. Fail at module load rather than silently.
  throw new Error(
    `${IDENTITY_REQUEST_OPERATION.operationId} became a recovery operation; the identity lifecycle gate would weaken`,
  );
}

function gateAuth(tenancy: Tenancy): AuthContext {
  return {
    subject: tenancy.userId ?? null,
    tenancy,
    scopes: [],
    platformOperator: false,
    source: "durable_native",
  };
}

// ---------------------------------------------------------------------------
// The persistence seam
// ---------------------------------------------------------------------------

interface RawSsoConfig {
  tenant_id: string;
  provider_kind: string;
  default_role: string;
  group_role_mapping_json: string;
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_client_secret_ref: string | null;
  oidc_redirect_uri: string | null;
  oidc_group_claim: string | null;
  saml_idp_entity_id: string | null;
  saml_idp_sso_url: string | null;
  saml_idp_certificate: string | null;
  saml_sp_entity_id: string | null;
  saml_acs_url: string | null;
  saml_email_attribute: string | null;
  saml_name_attribute: string | null;
  saml_groups_attribute: string | null;
  created_at_unix: number;
  updated_at_unix: number;
}

interface RawPendingFlow {
  state: string;
  tenant_id: string;
  provider_kind: string;
  code_verifier: string | null;
  nonce: string | null;
  request_id: string | null;
  created_at_unix: number;
  expires_at_unix: number;
}

function decodeGroupRoleMapping(json: string | null | undefined): Record<string, string> {
  if (typeof json !== "string" || json.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === "string") out[key] = value;
    }
    return out;
  } catch {
    // A corrupted mapping resolves to NO mapping, which falls through to
    // `defaultRole` — never to a role picked out of malformed JSON.
    return {};
  }
}

/** The full row, carrying BOTH protocols' columns (one table, one discriminant). */
export interface FullSsoProviderConfig extends StoredSsoProviderConfig {
  samlIdpEntityId: string | null;
  samlIdpSsoUrl: string | null;
  samlIdpCertificate: string | null;
  samlSpEntityId: string | null;
  samlAcsUrl: string | null;
  samlEmailAttribute: string | null;
  samlNameAttribute: string | null;
  samlGroupsAttribute: string | null;
}

function decodeSsoConfig(row: RawSsoConfig): FullSsoProviderConfig {
  return {
    tenantId: row.tenant_id,
    providerKind: row.provider_kind,
    defaultRole: row.default_role,
    groupRoleMapping: decodeGroupRoleMapping(row.group_role_mapping_json),
    oidcIssuer: row.oidc_issuer,
    oidcClientId: row.oidc_client_id,
    oidcClientSecretRef: row.oidc_client_secret_ref,
    oidcRedirectUri: row.oidc_redirect_uri,
    oidcGroupClaim: row.oidc_group_claim,
    samlIdpEntityId: row.saml_idp_entity_id,
    samlIdpSsoUrl: row.saml_idp_sso_url,
    samlIdpCertificate: row.saml_idp_certificate,
    samlSpEntityId: row.saml_sp_entity_id,
    samlAcsUrl: row.saml_acs_url,
    samlEmailAttribute: row.saml_email_attribute,
    samlNameAttribute: row.saml_name_attribute,
    samlGroupsAttribute: row.saml_groups_attribute,
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
  };
}

/**
 * `IdentityRepository` over this Worker's control database.
 *
 * Every method that needs D1 refuses LOUDLY when `controlDatabase` is `null`
 * (`CONTROL_PLANE_STORE = "memory"`, or no `DB` binding). The alternative — an
 * in-memory twin — would mean a deployment could authenticate an SSO login
 * against a table that vanishes on isolate recycle.
 */
export class ControlPlaneIdentityRepository implements IdentityRepository {
  readonly #deps: ControlPlaneDeps;

  constructor(deps: ControlPlaneDeps) {
    this.#deps = deps;
  }

  #db(): D1Database {
    const db = this.#deps.controlDatabase;
    if (db === null) {
      throw new Error("the identity surface requires the control database binding DB");
    }
    return db;
  }

  #session(): D1AdminConsoleSessionStore {
    return new D1AdminConsoleSessionStore(this.#db());
  }

  async #tenantDb(tenantId: string): Promise<D1Database> {
    const control = this.#db();
    await backfillTenantConfigurationPolicy(control, this.#deps.tenantDatabases, tenantId);
    return (await this.#deps.tenantDatabases.forTenant(tenantId)).db;
  }

  async getSsoProviderConfig(tenantId: string): Promise<FullSsoProviderConfig | null> {
    let row: RawSsoConfig | null;
    try {
      row = await (await this.#tenantDb(tenantId))
        .prepare("SELECT * FROM sso_provider_configs WHERE tenant_id = ?")
        .bind(tenantId)
        .first<RawSsoConfig>();
    } catch (error) {
      // An unregistered tenant has no configuration and must not materialize
      // storage just to answer the mounted route's 404. Registered-but-
      // unreachable object storage still propagates as an outage.
      if (error instanceof StorageError && error.kind === "not_found") return null;
      throw error;
    }
    return row === null ? null : decodeSsoConfig(row);
  }

  /** Upsert — `tenant_id` is the primary key, so a tenant has ONE config, ever. */
  async putSsoProviderConfig(config: FullSsoProviderConfig): Promise<void> {
    await (await this.#tenantDb(config.tenantId))
      .prepare(
        `INSERT INTO sso_provider_configs (
           tenant_id, provider_kind, default_role, group_role_mapping_json,
           oidc_issuer, oidc_client_id, oidc_client_secret_ref, oidc_redirect_uri, oidc_group_claim,
           saml_idp_entity_id, saml_idp_sso_url, saml_idp_certificate, saml_sp_entity_id,
           saml_acs_url, saml_email_attribute, saml_name_attribute, saml_groups_attribute,
           created_at_unix, updated_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id) DO UPDATE SET
           provider_kind = excluded.provider_kind,
           default_role = excluded.default_role,
           group_role_mapping_json = excluded.group_role_mapping_json,
           oidc_issuer = excluded.oidc_issuer,
           oidc_client_id = excluded.oidc_client_id,
           oidc_client_secret_ref = excluded.oidc_client_secret_ref,
           oidc_redirect_uri = excluded.oidc_redirect_uri,
           oidc_group_claim = excluded.oidc_group_claim,
           saml_idp_entity_id = excluded.saml_idp_entity_id,
           saml_idp_sso_url = excluded.saml_idp_sso_url,
           saml_idp_certificate = excluded.saml_idp_certificate,
           saml_sp_entity_id = excluded.saml_sp_entity_id,
           saml_acs_url = excluded.saml_acs_url,
           saml_email_attribute = excluded.saml_email_attribute,
           saml_name_attribute = excluded.saml_name_attribute,
           saml_groups_attribute = excluded.saml_groups_attribute,
           updated_at_unix = excluded.updated_at_unix`,
      )
      .bind(
        config.tenantId,
        config.providerKind,
        config.defaultRole,
        JSON.stringify(config.groupRoleMapping),
        config.oidcIssuer,
        config.oidcClientId,
        config.oidcClientSecretRef,
        config.oidcRedirectUri,
        config.oidcGroupClaim,
        config.samlIdpEntityId,
        config.samlIdpSsoUrl,
        config.samlIdpCertificate,
        config.samlSpEntityId,
        config.samlAcsUrl,
        config.samlEmailAttribute,
        config.samlNameAttribute,
        config.samlGroupsAttribute,
        config.createdAtUnix,
        config.updatedAtUnix,
      )
      .run();
  }

  async deleteSsoProviderConfig(tenantId: string): Promise<boolean> {
    const result = await (await this.#tenantDb(tenantId))
      .prepare("DELETE FROM sso_provider_configs WHERE tenant_id = ?")
      .bind(tenantId)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }

  async insertSsoPendingFlow(flow: StoredSsoPendingFlow): Promise<void> {
    await this.#db()
      .prepare(
        `INSERT INTO sso_pending_flows (
           state, tenant_id, provider_kind, code_verifier, nonce, request_id,
           created_at_unix, expires_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        flow.state,
        flow.tenantId,
        flow.providerKind,
        flow.codeVerifier,
        flow.nonce,
        flow.requestId,
        flow.createdAtUnix,
        flow.expiresAtUnix,
      )
      .run();
  }

  /**
   * THE REPLAY DEFENCE, and it is ONE statement.
   *
   * `DELETE … WHERE state = ? AND expires_at_unix > ? RETURNING *` consumes and
   * reads atomically, so two concurrent callbacks carrying the same `state`
   * cannot both succeed and an expired row is never a stale hit. A `SELECT`
   * followed by a `DELETE` would pass every test in `packages/{identity,sso}`
   * — they exercise the in-memory reference — and reintroduce replay in
   * production. `test/sso-store-contract.test.ts` runs the package's own
   * exported contract against THIS implementation for exactly that reason.
   */
  async takeSsoPendingFlow(state: string, nowUnix: number): Promise<StoredSsoPendingFlow | null> {
    // NOTE the absence of `AND expires_at_unix > ?` in the DELETE. Presenting a
    // state BURNS it even when it has already expired — that is the package's
    // exported contract ("presenting an EXPIRED state still burns it"), and
    // filtering in SQL instead would leave an expired row alive for a second
    // attempt under a different clock. The expiry decision is made below, on a
    // row that no longer exists either way.
    const row = await this.#db()
      .prepare("DELETE FROM sso_pending_flows WHERE state = ? RETURNING *")
      .bind(state)
      .first<RawPendingFlow>();
    if (row === null) return null;
    if (row.expires_at_unix <= nowUnix) return null;
    return {
      state: row.state,
      tenantId: row.tenant_id,
      providerKind: row.provider_kind,
      codeVerifier: row.code_verifier,
      nonce: row.nonce,
      requestId: row.request_id,
      createdAtUnix: row.created_at_unix,
      expiresAtUnix: row.expires_at_unix,
    };
  }

  async getAdminUserByEmail(email: string): Promise<StoredAdminUser | null> {
    return (await this.#session().getUserByEmail(email)) as StoredAdminUser | null;
  }

  async getAdminUserById(userId: string): Promise<StoredAdminUser | null> {
    return (await this.#session().getUserById(userId)) as StoredAdminUser | null;
  }

  async upsertAdminUser(user: StoredAdminUser): Promise<void> {
    await this.#session().upsertUser(user);
  }

  async listAdminUserMembershipsByTenant(tenantId: string): Promise<StoredAdminUserMembership[]> {
    return [...(await this.#session().listMembershipsByTenant(tenantId))];
  }

  async listAdminUserMembershipsByUser(userId: string): Promise<StoredAdminUserMembership[]> {
    return [...(await this.#session().listMembershipsByUser(userId))];
  }

  async upsertAdminUserMembership(membership: StoredAdminUserMembership): Promise<void> {
    await this.#session().upsertMembership(membership);
  }

  async deleteAdminUserMembership(userId: string, tenantId: string): Promise<boolean> {
    return await this.#session().deleteMembership(userId, tenantId);
  }

  async revokeAdminUserRefreshTokensForTenant(
    userId: string,
    tenantId: string,
    nowUnix: number,
  ): Promise<void> {
    await this.#db()
      .prepare(
        `UPDATE admin_user_refresh_tokens
            SET revoked_at_unix = ?
          WHERE user_id = ? AND tenant_id = ? AND revoked_at_unix IS NULL`,
      )
      .bind(nowUnix, userId, tenantId)
      .run();
  }

  async revokeAllAdminUserRefreshTokens(userId: string, nowUnix: number): Promise<void> {
    await this.#db()
      .prepare(
        `UPDATE admin_user_refresh_tokens
            SET revoked_at_unix = ?
          WHERE user_id = ? AND revoked_at_unix IS NULL`,
      )
      .bind(nowUnix, userId)
      .run();
  }

  async revokeAdminConsoleSessionKeys(tenantId: string, userId: string): Promise<void> {
    await revokeAdminConsoleSessionKeys(this.#deps, tenantId, userId);
  }

  async getTenantAccount(tenantId: string): Promise<StoredTenantAccount | null> {
    const record = await this.#deps.store.get(
      TENANT_ACCOUNTS_COLLECTION,
      { kind: "platform_operator" },
      tenantId,
    );
    if (record === null) return null;
    return { id: String(record.id), name: String(record.name ?? "") };
  }

  async resolveDefaultWorkspace(tenantId: string): Promise<StoredWorkspaceRef | null> {
    const page = await this.#deps.store.list(
      WORKSPACES_COLLECTION,
      { kind: "tenant", tenantId },
      LIST_EVERYTHING,
    );
    const workspace = page.items.find((item) => item.tenant_id === tenantId);
    if (workspace === undefined) return null;
    return {
      id: String(workspace.id),
      projectId: String(workspace.project_id ?? ""),
      tenantId,
    };
  }

  /**
   * Writes the SCIM provisioning token as an ORDINARY virtual key — the same
   * document `POST /admin/v1/virtual-keys` writes — and then projects the two
   * credential rows.
   *
   * Both halves are required: the document alone is invisible to
   * `deps.apiKeys.authenticate`, so a token that "was created" would never
   * authenticate, and the SCIM surface would be permanently 401.
   */
  async upsertApiKeyRecord(key: StoredApiKeyRecord): Promise<void> {
    const record: StoreRecord = {
      id: key.id,
      name: key.name,
      tenant_id: key.tenantId,
      project_id: key.projectId,
      workspace_id: key.workspaceId,
      key_hash: key.keyHash,
      key_prefix: key.keyPrefix,
      last4: key.last4,
      enabled: key.enabled,
      revoked: false,
      scopes: [...key.scopes],
      allowed_models: [],
      allowed_providers: [],
      created_at: key.createdAtUnix,
    };
    const stored = await this.#deps.store.create(
      VIRTUAL_KEYS_COLLECTION,
      { kind: "tenant", tenantId: key.tenantId },
      record,
    );
    const controlDb = this.#deps.controlDatabase;
    if (controlDb === null || !virtualKeyProjectable(stored)) return;
    const handle = await tenantDatabaseFor(this.#deps.tenantDatabases, key.tenantId);
    if (handle === null) return;
    await projectVirtualKey(controlDb, handle, stored, key.createdAtUnix, "loosen");
  }

  /** Throws when the lifecycle chain refuses. Never returns a decision to ignore. */
  async requireUsableTenancy(_seam: LifecycleSeam, refs: TenancyRefs): Promise<void> {
    const decision = await this.#deps.lifecycle.admit(
      gateAuth({
        tenantId: refs.tenantId,
        projectId: refs.projectId,
        workspaceId: refs.workspaceId,
      }),
      IDENTITY_REQUEST_OPERATION,
    );
    if (decision.admitted === "unavailable") {
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
}

// ---------------------------------------------------------------------------
// The session seam
// ---------------------------------------------------------------------------

/**
 * `AdminSessionPort` over `session/`.
 *
 * Every method delegates to the machinery the password-login surface already
 * uses, so an SSO session and a password session are the SAME credential with
 * the same TTLs, the same refresh-token hashing and the same #514/#517 key
 * ladder. A second implementation here is how the two drift.
 */
export class ControlPlaneAdminSessionPort implements AdminSessionPort {
  readonly #deps: ControlPlaneDeps;
  readonly #jwtSecret: string | null;

  constructor(deps: ControlPlaneDeps, jwtSecret: string | null) {
    this.#deps = deps;
    this.#jwtSecret = jwtSecret;
  }

  #secret(): string {
    if (this.#jwtSecret === null) {
      throw new HttpError(
        503,
        "admin_console_unconfigured",
        `admin console sessions require the ${ADMIN_CONSOLE_JWT_SECRET_BINDING} secret binding`,
      );
    }
    return this.#jwtSecret;
  }

  #store(): D1AdminConsoleSessionStore {
    const db = this.#deps.controlDatabase;
    if (db === null) {
      throw new HttpError(
        503,
        "admin_console_unconfigured",
        "admin console sessions require the control database binding DB",
      );
    }
    return new D1AdminConsoleSessionStore(db);
  }

  /**
   * The token's user AND their membership in the tenant the token names.
   *
   * NEVER `memberships[0]`: a multi-tenant admin's SCIM token must be minted
   * for the tenant their session was issued for, not whichever membership
   * sorts first. That is the #232 rule, and it is enforced here by looking the
   * membership up BY the claim rather than by picking one.
   */
  async currentAdminSession(
    token: string,
  ): Promise<{ user: StoredAdminUser; membership: StoredAdminUserMembership } | null> {
    const claims = await verifyAdminAccessToken(this.#secret(), token);
    if (claims === null) return null;
    const store = this.#store();
    const user = await store.getUserById(claims.sub);
    if (user === null || user.disabledAtUnix !== null) return null;
    const memberships = await store.listMembershipsByUser(claims.sub);
    const membership = memberships.find((entry) => entry.tenantId === claims.tenant_id);
    if (membership === undefined) return null;
    return { user: user as StoredAdminUser, membership: membership as StoredAdminUserMembership };
  }

  async issueSession(args: {
    userId: string;
    email: string;
    tenantId: string;
    role: string;
  }): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
    const now = identityClock.nowUnix();
    const role = membershipRoleFromStored(args.role);
    const accessToken = await signAdminAccessToken(this.#secret(), {
      sub: args.userId,
      email: args.email,
      tenant_id: args.tenantId,
      role,
      iat: now,
      exp: now + ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
    });
    const refreshToken = generateRandomHex(32);
    await this.#store().upsertRefreshToken({
      id: nextId("rt"),
      userId: args.userId,
      // Hashed, never plaintext — a durable-storage read cannot mint a session.
      tokenHash: await sha256Hex(refreshToken),
      tenantId: args.tenantId,
      role,
      createdAtUnix: now,
      expiresAtUnix: now + ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
      revokedAtUnix: null,
    });
    return { accessToken, refreshToken, expiresIn: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS };
  }

  async provisionGatewayApiKey(args: {
    workspaceId: string;
    projectId: string;
    tenantId: string;
    userId: string;
    role: string;
  }): Promise<string> {
    return await provisionGatewayApiKey(this.#deps, {
      tenantId: args.tenantId,
      projectId: args.projectId,
      workspaceId: args.workspaceId,
      adminUserId: args.userId,
      role: membershipRoleFromStored(args.role),
    });
  }

  async mintVirtualApiKeySecret(): Promise<{
    secret: string;
    keyPrefix: string;
    keyHash: string;
    last4: string;
  }> {
    const secret = `fg_${generateRandomHex(24)}`;
    return {
      secret,
      keyPrefix: secret.slice(0, 16),
      keyHash: await sha256Hex(secret),
      last4: secret.slice(-4),
    };
  }
}

// ---------------------------------------------------------------------------
// The credential seam
// ---------------------------------------------------------------------------

/**
 * `ApiKeyAuthenticatorPort` for SCIM, over the SAME resolver the 214 admin
 * operations authenticate with.
 *
 * Consequence, and it is the point: revoking or rotating a SCIM token through
 * `/admin/v1/virtual-keys` takes effect here with no second code path, and a
 * suspended KEY is refused before the SCIM scope check ever runs.
 *
 * Every non-`resolved` outcome maps to `null`, i.e. a 401. Widening any of them
 * to a pass would let a disabled or budget-exhausted key provision users.
 */
export function scimApiKeyAuthenticator(deps: ControlPlaneDeps): IdentityApiKeyAuthenticatorPort {
  return {
    async authenticate(token: string): Promise<ApiKeyDecision | null> {
      const resolution = await deps.apiKeys.authenticate(token);
      if (resolution.outcome !== "resolved") return null;
      const auth = resolution.auth;
      return {
        apiKeyId: auth.subject ?? "",
        // Verbatim. NOT widened by `platformOperator`: a platform key is not
        // scoped to a tenant, and `resolveScimTenant` refuses a decision with
        // no `organizationId` rather than picking one.
        scopes: [...auth.scopes],
        tenant: {
          organizationId: auth.tenancy.tenantId ?? null,
          projectId: auth.tenancy.projectId ?? null,
          workspaceId: auth.tenancy.workspaceId ?? null,
        },
      };
    },
  };
}

/**
 * `SecretResolverPort` for the OIDC `client_secret_ref`.
 *
 * The stored row holds a REFERENCE (`env://NAME`), never a secret, so a
 * control-plane row read can never leak a live IdP credential. Anything that
 * does not parse as a reference resolves to `null`, which fails the login
 * closed rather than treating the literal string as the secret.
 */
export function identitySecretResolver(env: unknown): SecretResolverPort {
  const resolver = new EnvSecretResolver((env ?? {}) as EnvLike);
  return {
    async resolve(reference: string): Promise<string | null> {
      try {
        const parsed = parseSecretRef(reference);
        return await resolver.resolve(parsed);
      } catch {
        return null;
      }
    },
  };
}

// ---------------------------------------------------------------------------
// SAML ports
// ---------------------------------------------------------------------------

/**
 * `SamlPorts` over the SAME two tables and the SAME atomic `take`.
 *
 * `packages/sso` models the row without the OIDC-only `nonce` column, so the
 * mapping drops it — one table, two protocol views, one `provider_kind`
 * discriminant.
 */
export function samlPorts(repository: ControlPlaneIdentityRepository): SamlPorts {
  return {
    configs: {
      async get(tenantId: string): Promise<SamlStoredSsoProviderConfig | null> {
        return await repository.getSsoProviderConfig(tenantId);
      },
    },
    flows: {
      async insert(flow: SsoPendingFlow): Promise<void> {
        await repository.insertSsoPendingFlow({ ...flow, nonce: null });
      },
      async take(state: string, nowUnix: number): Promise<SsoPendingFlow | null> {
        const flow = await repository.takeSsoPendingFlow(state, nowUnix);
        if (flow === null) return null;
        // `nonce` is the OIDC-only column. Dropping it here keeps the SAML view
        // of the shared row EXACTLY the shape `packages/sso` declares, which is
        // what its exported store contract asserts field-for-field.
        const { nonce: _nonce, ...samlView } = flow;
        return samlView;
      },
    },
    now: () => identityClock.nowUnix(),
    randomHex: webCryptoRandomHex,
  };
}

// ---------------------------------------------------------------------------
// THE resolver the composition root passes to `createIdentityRoutes`
// ---------------------------------------------------------------------------

/** Everything the identity surfaces need, resolved per request from bindings. */
export interface ResolvedIdentity extends IdentityDeps {
  readonly controlPlane: ControlPlaneDeps;
  readonly repository: ControlPlaneIdentityRepository;
  readonly saml: SamlPorts;
}

/**
 * Built per request, exactly like `resolveDeps` — the D1 handles come off
 * `c.env`, so there is nothing isolate-global here except the JWKS cache, which
 * is keyed by the IdP's own URI and holds only PUBLIC keys.
 */
export function resolveIdentityDeps(c: Context<ControlPlaneEnv>): ResolvedIdentity {
  const controlPlane = c.get("deps") as ControlPlaneDeps;
  const repository = new ControlPlaneIdentityRepository(controlPlane);
  return {
    controlPlane,
    repository,
    saml: samlPorts(repository),
    secrets: identitySecretResolver(c.env),
    session: new ControlPlaneAdminSessionPort(controlPlane, adminConsoleJwtSecret(c.env)),
    clock: identityClock,
    random: identityRandom,
    fetch: (url, init) => fetch(url, init),
    jwks: jwksCache(),
    apiKeys: scimApiKeyAuthenticator(controlPlane),
  };
}

export { PROJECTS_COLLECTION };
