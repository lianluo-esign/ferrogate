/**
 * The seams `@ferrogate/identity` is composed over.
 *
 * Clean-room port of the storage/session/secret surfaces
 * `crates/ferrogate-auth-service/src/{sso,scim}.rs` reach through
 * (`console.repositories`, `console.secret_resolver`, `AdminConsoleState`).
 * Everything here is an INTERFACE: this package holds the OIDC and SCIM
 * decisions and none of the persistence, so the D1 implementation lives in the
 * composition root that mounts it and there is exactly one implementation of
 * every authorization predicate — in `src/`.
 */

/** A per-tenant SSO provider configuration row (`StoredSsoProviderConfig`). */
export interface StoredSsoProviderConfig {
  tenantId: string;
  /** `"oidc"` or `"saml"`. Anything else fails closed. */
  providerKind: string;
  /** Tier assigned on first login when no group maps. */
  defaultRole: string;
  /** IdP group name → tenant tier. */
  groupRoleMapping: Record<string, string>;
  oidcIssuer: string | null;
  oidcClientId: string | null;
  /** A `@ferrogate/secrets` reference (`env://…`), never a plaintext secret. */
  oidcClientSecretRef: string | null;
  oidcRedirectUri: string | null;
  oidcGroupClaim: string | null;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** An in-flight SSO handshake (`StoredSsoPendingFlow`). */
export interface StoredSsoPendingFlow {
  /** The opaque CSRF `state`, and the row's primary key. */
  state: string;
  tenantId: string;
  providerKind: string;
  /** PKCE (RFC 7636) verifier, OIDC only. */
  codeVerifier: string | null;
  /** OIDC `nonce` — binds the ID token to THIS authorize request. */
  nonce: string | null;
  /** SAML `AuthnRequest` id, SAML only. */
  requestId: string | null;
  createdAtUnix: number;
  expiresAtUnix: number;
}

export interface StoredAdminUser {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  superadmin: boolean;
  createdAtUnix: number;
  updatedAtUnix: number;
  lastLoginAtUnix: number | null;
  /** Non-null ⇒ globally disabled. */
  disabledAtUnix: number | null;
}

export interface StoredAdminUserMembership {
  id: string;
  userId: string;
  tenantId: string;
  role: string;
  createdAtUnix: number;
}

export interface StoredTenantAccount {
  id: string;
  name: string;
}

export interface StoredWorkspaceRef {
  id: string;
  projectId: string;
  tenantId: string;
}

/** The virtual-API-key row a minted SCIM provisioning token becomes. */
export interface StoredApiKeyRecord {
  id: string;
  tenantId: string;
  projectId: string;
  workspaceId: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  last4: string;
  enabled: boolean;
  scopes: readonly string[];
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** The tenancy-lifecycle gate seam (`LifecycleSeam` in `ferrogate-storage`). */
export type LifecycleSeam = "attach" | "request";

export interface TenancyRefs {
  tenantId: string | null;
  projectId: string | null;
  workspaceId: string | null;
}

/** What the api-key authenticator resolves a bearer token to. */
export interface ApiKeyDecision {
  apiKeyId: string;
  scopes: readonly string[];
  tenant: {
    organizationId: string | null;
    projectId: string | null;
    workspaceId: string | null;
  };
}

/**
 * The persistence seam. Mirrors the `console.repositories` calls `sso.rs` and
 * `scim.rs` make, one method per call, nothing more.
 */
export interface IdentityRepository {
  getSsoProviderConfig(tenantId: string): Promise<StoredSsoProviderConfig | null>;

  insertSsoPendingFlow(flow: StoredSsoPendingFlow): Promise<void>;
  /**
   * Atomically consumes the flow: it MUST be single-use (a second call with
   * the same `state` returns `null`) and MUST return `null` for an entry whose
   * `expiresAtUnix` has passed. Both properties are the CSRF/replay defence,
   * so an implementation that merely reads is a defect.
   */
  takeSsoPendingFlow(state: string, nowUnix: number): Promise<StoredSsoPendingFlow | null>;

  getAdminUserByEmail(email: string): Promise<StoredAdminUser | null>;
  getAdminUserById(userId: string): Promise<StoredAdminUser | null>;
  upsertAdminUser(user: StoredAdminUser): Promise<void>;

  listAdminUserMembershipsByTenant(tenantId: string): Promise<StoredAdminUserMembership[]>;
  listAdminUserMembershipsByUser(userId: string): Promise<StoredAdminUserMembership[]>;
  upsertAdminUserMembership(membership: StoredAdminUserMembership): Promise<void>;
  deleteAdminUserMembership(userId: string, tenantId: string): Promise<boolean>;

  revokeAdminUserRefreshTokensForTenant(
    userId: string,
    tenantId: string,
    nowUnix: number,
  ): Promise<void>;
  revokeAllAdminUserRefreshTokens(userId: string, nowUnix: number): Promise<void>;
  /**
   * Revokes the gateway virtual keys minted alongside this user's console
   * sessions FOR THIS TENANT (issue #517). Revoking only refresh tokens leaves
   * a deprovisioned user holding a live `admin.write` Admin API credential.
   */
  revokeAdminConsoleSessionKeys(tenantId: string, userId: string): Promise<void>;

  getTenantAccount(tenantId: string): Promise<StoredTenantAccount | null>;
  resolveDefaultWorkspace(tenantId: string): Promise<StoredWorkspaceRef | null>;
  upsertApiKeyRecord(key: StoredApiKeyRecord): Promise<void>;

  /** Throws when the tenancy is suspended/deleted at this seam. */
  requireUsableTenancy(seam: LifecycleSeam, refs: TenancyRefs): Promise<void>;
}

/** Resolves a bearer token to its key decision, or `null`. */
export interface ApiKeyAuthenticatorPort {
  authenticate(token: string): Promise<ApiKeyDecision | null>;
}

/** Resolves a `@ferrogate/secrets` reference to its value. */
export interface SecretResolverPort {
  resolve(ref: string): Promise<string | null>;
}

/** The admin-console session machinery this package reuses but does not own. */
export interface AdminSessionPort {
  /** The caller's session + their membership in the session's tenant. */
  currentAdminSession(
    token: string,
  ): Promise<{ user: StoredAdminUser; membership: StoredAdminUserMembership } | null>;
  issueSession(args: {
    userId: string;
    email: string;
    tenantId: string;
    role: string;
  }): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }>;
  /**
   * Mints (and rotates away the previous) console gateway key at the given
   * tier. Throws when the tenancy refuses it — the caller must NOT fall back
   * to issuing a session (#514).
   */
  provisionGatewayApiKey(args: {
    workspaceId: string;
    projectId: string;
    tenantId: string;
    userId: string;
    role: string;
  }): Promise<string>;
  /** Fresh virtual-key secret + its stored (hashed) material. */
  mintVirtualApiKeySecret(): Promise<{
    secret: string;
    keyPrefix: string;
    keyHash: string;
    last4: string;
  }>;
}

export interface IdentityClock {
  nowUnix(): number;
}

export interface IdentityRandom {
  /** `byteLength` bytes of CSPRNG output, hex encoded (2 chars per byte). */
  hex(byteLength: number): string;
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** The shape every handler in this package returns: a status and a JSON body. */
export interface IdentityResponse {
  status: number;
  body: unknown;
  /** `application/scim+json` for SCIM resources, plain JSON otherwise. */
  scim?: boolean;
}
