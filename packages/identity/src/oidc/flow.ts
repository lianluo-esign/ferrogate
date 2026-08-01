/**
 * The OIDC Authorization Code + PKCE relying-party flow.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/sso.rs`
 * (`handle_sso_authorize`, `handle_sso_callback`, `complete_sso_login`) —
 * issues #160, #283, #232, #514, #517.
 *
 * The callback is a LADDER, and every rung fails closed:
 *
 * ```
 *   state → single-use pending flow      (CSRF; unknown/expired/replayed → 401)
 *   config still OIDC                    (removed mid-flow → 500)
 *   client secret resolves               (never persisted in plaintext)
 *   code + PKCE verifier → token         (an intercepted code alone is useless)
 *   kid → JWKS                           (unpublished key → 401)
 *   signature                            (forged token → 401)
 *   iss / aud / exp / iat / nonce        (other-audience, replayed, injected → 401)
 *   email present + not marked unverified
 *   membership-in-THIS-tenant            (#232 cross-tenant takeover guard)
 *   account not disabled
 *   gateway key mint                     (#514 suspended tenancy → no session)
 *   session
 * ```
 */
import {
  internalError,
  lifecycleError,
  notFound,
  storageError,
  unauthorized,
  unprocessable,
} from "../errors.js";
import { membershipRoleFromStored } from "../membership-role.js";
import type {
  AdminSessionPort,
  FetchLike,
  IdentityClock,
  IdentityRandom,
  IdentityRepository,
  IdentityResponse,
  SecretResolverPort,
  StoredAdminUser,
} from "../ports.js";
import { UNUSABLE_PASSWORD_HASH, isValidEmail, nextId } from "../util.js";
import { validateIdTokenClaims } from "./claims.js";
import { type ResolvedOidcConfig, resolveOidcConfig } from "./config.js";
import { fetchOidcDiscovery } from "./discovery.js";
import type { JwksCache } from "./jwks.js";
import { SUPPORTED_JWS_ALGORITHMS, decodeJwsHeader, verifyCompactJws } from "./jws.js";
import { generateNonce, generatePkcePair, generateState } from "./pkce.js";

/**
 * How long an in-flight SSO handshake stays valid. Ten minutes: the browser
 * may sit at the IdP through a password prompt and an MFA challenge, but a
 * pending flow is a live authentication capability, so it must not linger.
 */
export const SSO_FLOW_TTL_SECONDS = 600;

/** The scopes requested on the authorize leg. */
export const OIDC_SCOPE = "openid email profile";

export interface OidcDeps {
  repository: IdentityRepository;
  secrets: SecretResolverPort;
  session: AdminSessionPort;
  clock: IdentityClock;
  random: IdentityRandom;
  fetch: FetchLike;
  jwks: JwksCache;
}

/**
 * `GET /v1/admin/auth/sso/authorize?tenant_id=…` — starts the handshake.
 *
 * Unauthenticated by design (the browser is not logged in yet) and returns the
 * URL as JSON rather than a 302, so a JSON-only client can drive it too.
 */
export async function startOidcAuthorize(
  deps: OidcDeps,
  tenantId: string,
): Promise<IdentityResponse> {
  let stored: Awaited<ReturnType<IdentityRepository["getSsoProviderConfig"]>>;
  try {
    stored = await deps.repository.getSsoProviderConfig(tenantId);
  } catch (error) {
    return storageError(error);
  }
  if (!stored) return notFound("SSO is not configured for this tenant");
  const config = resolveOidcConfig(stored);
  if (!config) {
    return unprocessable(
      "this tenant is not configured for OIDC SSO; use the SAML authorize endpoint",
    );
  }

  // Discovery FIRST: a pending flow is a credential-shaped row, so it is not
  // written for a handshake that cannot start.
  const discovery = await fetchOidcDiscovery(deps.fetch, config.issuer);
  if (!discovery) return internalError("OIDC discovery failed");

  const { codeVerifier, codeChallenge } = await generatePkcePair(deps.random);
  const state = generateState(deps.random);
  const nonce = generateNonce(deps.random);
  const now = deps.clock.nowUnix();
  try {
    await deps.repository.insertSsoPendingFlow({
      state,
      tenantId,
      providerKind: "oidc",
      codeVerifier,
      nonce,
      requestId: null,
      createdAtUnix: now,
      expiresAtUnix: now + SSO_FLOW_TTL_SECONDS,
    });
  } catch (error) {
    return storageError(error);
  }

  const authorizeUrl = new URL(discovery.authorizationEndpoint);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", config.clientId);
  authorizeUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizeUrl.searchParams.set("scope", OIDC_SCOPE);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("nonce", nonce);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  return { status: 200, body: { authorize_url: authorizeUrl.toString(), state } };
}

/** `GET /v1/admin/auth/sso/callback?code=…&state=…` — completes the handshake. */
export async function completeOidcCallback(
  deps: OidcDeps,
  params: { code: string; state: string },
): Promise<IdentityResponse> {
  const now = deps.clock.nowUnix();

  // --- rung 1: the state must be one WE issued, unexpired and unused -------
  // This runs before any outbound call, so a forged state costs nothing and
  // leaks nothing about whether the tenant has SSO configured.
  let flow: Awaited<ReturnType<IdentityRepository["takeSsoPendingFlow"]>>;
  try {
    flow = await deps.repository.takeSsoPendingFlow(params.state, now);
  } catch (error) {
    return storageError(error);
  }
  if (!flow) return unauthorized("unknown, expired, or already-used SSO state");
  if (flow.providerKind !== "oidc" || !flow.codeVerifier || !flow.nonce) {
    return unprocessable("this pending flow is not an OIDC flow");
  }

  // --- rung 2: the tenant is still configured for OIDC ---------------------
  let stored: Awaited<ReturnType<IdentityRepository["getSsoProviderConfig"]>>;
  try {
    stored = await deps.repository.getSsoProviderConfig(flow.tenantId);
  } catch (error) {
    return storageError(error);
  }
  if (!stored) return internalError("SSO configuration was removed mid-flow");
  const config = resolveOidcConfig(stored);
  if (!config) return internalError("SSO configuration is no longer OIDC");

  // --- rung 3: resolve the client secret just-in-time ----------------------
  let clientSecret: string | null;
  try {
    clientSecret = await deps.secrets.resolve(config.clientSecretRef);
  } catch {
    return internalError("failed to resolve OIDC client secret");
  }
  if (!clientSecret) {
    return internalError("OIDC client_secret_ref did not resolve to a secret");
  }

  const discovery = await fetchOidcDiscovery(deps.fetch, config.issuer);
  if (!discovery) return internalError("OIDC discovery failed");

  // --- rung 4: exchange the code, presenting the stashed PKCE verifier -----
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: clientSecret,
    code_verifier: flow.codeVerifier,
  });
  let tokenResponse: Response;
  try {
    tokenResponse = await deps.fetch(discovery.tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: form.toString(),
    });
  } catch {
    return internalError("token exchange failed");
  }
  if (!tokenResponse.ok) return internalError("token exchange was refused by the IdP");
  let tokenBody: unknown;
  try {
    tokenBody = await tokenResponse.json();
  } catch {
    return internalError("invalid token endpoint response");
  }
  const idToken = (tokenBody as { id_token?: unknown } | null)?.id_token;
  if (typeof idToken !== "string" || idToken.length === 0) {
    return internalError("token response did not include an id_token");
  }

  // --- rung 5: pin the token to a PUBLISHED key ---------------------------
  const header = decodeJwsHeader(idToken);
  if (!header) return unauthorized("invalid ID token header");
  if (!header.kid) return unauthorized("ID token is missing a key id (kid)");
  if (!SUPPORTED_JWS_ALGORITHMS.includes(header.alg)) {
    return unauthorized(`unsupported ID token algorithm ${JSON.stringify(header.alg)}`);
  }
  const jwk = await deps.jwks.findKey(discovery.jwksUri, header.kid);
  if (!jwk) return unauthorized("ID token key id was not found in the IdP's JWKS");

  // --- rung 6: the signature ----------------------------------------------
  const verification = await verifyCompactJws(idToken, jwk, header.alg);
  if (!verification.ok)
    return unauthorized(`ID token signature check failed (${verification.reason})`);

  // --- rung 7: the registered claims --------------------------------------
  const claims = validateIdTokenClaims(verification.payload, {
    issuer: config.issuer,
    audience: config.clientId,
    nonce: flow.nonce,
    nowUnix: now,
  });
  if (!claims.ok) return unauthorized(`ID token validation failed (${claims.reason})`);

  // --- rung 8: a usable, IdP-affirmed email -------------------------------
  const rawEmail = verification.payload.email;
  const email = typeof rawEmail === "string" ? rawEmail.toLowerCase() : "";
  if (!isValidEmail(email)) {
    return unprocessable("ID token did not include a usable email claim");
  }
  // An absent `email_verified` is tolerated (many IdPs omit it); an explicit
  // `false` is a tenant-controlled IdP asserting someone else's address.
  if (verification.payload.email_verified === false) {
    return unauthorized("the identity provider reported this email as unverified");
  }
  const rawName = verification.payload.name;
  const displayName = typeof rawName === "string" && rawName.length > 0 ? rawName : email;
  const rawGroups = verification.payload[config.groupClaim];
  const groups = Array.isArray(rawGroups)
    ? rawGroups.filter((value): value is string => typeof value === "string")
    : [];

  return completeSsoLogin(deps, {
    tenantId: flow.tenantId,
    email,
    displayName,
    groups,
    groupRoleMapping: config.groupRoleMapping,
    defaultRole: config.defaultRole,
  });
}

/** The tenant role this user's membership row currently carries, if any. */
async function membershipRoleInTenant(
  repository: IdentityRepository,
  tenantId: string,
  userId: string,
): Promise<string | null> {
  const memberships = await repository.listAdminUserMembershipsByTenant(tenantId);
  return memberships.find((membership) => membership.userId === userId)?.role ?? null;
}

export interface CompleteSsoLoginArgs {
  tenantId: string;
  email: string;
  displayName: string;
  groups: readonly string[];
  groupRoleMapping: Record<string, string>;
  defaultRole: string;
}

/**
 * The shared tail of an OIDC or SAML login, once a VERIFIED email, display
 * name and IdP group list have been established.
 *
 * Exported because `packages/sso` (the SAML half) must land in exactly this
 * function rather than reimplementing the JIT-provisioning and takeover rules
 * — the Rust reference shares `complete_sso_login` between both legs for the
 * same reason, and a second copy is a second place for the #232 guard to go
 * missing.
 */
export async function completeSsoLogin(
  deps: Pick<OidcDeps, "repository" | "session" | "clock" | "random">,
  args: CompleteSsoLoginArgs,
): Promise<IdentityResponse> {
  const { repository, session, clock, random } = deps;

  // Resolve the IdP's groups to a tier. `from_stored` semantics, NOT `parse`:
  // a config persisted before the #517 validator existed can still hold junk,
  // and junk must resolve to the LEAST privilege, never default up to owner.
  const mappedRoleSource =
    args.groups.map((group) => args.groupRoleMapping[group]).find((role) => role !== undefined) ??
    args.defaultRole;
  const mappedRole = membershipRoleFromStored(mappedRoleSource);

  let existing: StoredAdminUser | null;
  try {
    existing = await repository.getAdminUserByEmail(args.email);
  } catch (error) {
    return storageError(error);
  }

  let user: StoredAdminUser;
  if (existing) {
    // #232 CROSS-TENANT ACCOUNT-TAKEOVER GUARD.
    //
    // SSO trust is per-tenant (each tenant owner freely configures their own
    // IdP) but admin accounts are keyed GLOBALLY by email. Without this check
    // a tenant owner running their own IdP could assert a victim's address and
    // this callback would mint a session bound to the victim's global account.
    // Only an account that is ALREADY a member of this tenant may be signed in
    // by this tenant's IdP; a brand-new address is JIT-created below and
    // belongs only here.
    try {
      if ((await membershipRoleInTenant(repository, args.tenantId, existing.id)) === null) {
        return unauthorized("this account is not provisioned for single sign-on in this tenant");
      }
    } catch (error) {
      return storageError(error);
    }
    user = existing;
  } else {
    const now = clock.nowUnix();
    user = {
      id: nextId("user", random),
      email: args.email,
      passwordHash: UNUSABLE_PASSWORD_HASH,
      displayName: args.displayName,
      superadmin: false,
      createdAtUnix: now,
      updatedAtUnix: now,
      lastLoginAtUnix: now,
      disabledAtUnix: null,
    };
    try {
      await repository.upsertAdminUser(user);
    } catch (error) {
      return storageError(error);
    }
  }

  if (user.disabledAtUnix !== null) return unauthorized("this account has been disabled");

  // A role is only set on FIRST join — a later SSO login must never silently
  // override a tier an owner changed afterward through the team API.
  let effectiveRole: string;
  try {
    const current = await membershipRoleInTenant(repository, args.tenantId, user.id);
    if (current !== null) {
      effectiveRole = membershipRoleFromStored(current);
    } else {
      await repository.upsertAdminUserMembership({
        id: nextId("membership", random),
        userId: user.id,
        tenantId: args.tenantId,
        role: mappedRole,
        createdAtUnix: clock.nowUnix(),
      });
      effectiveRole = mappedRole;
    }
  } catch (error) {
    return storageError(error);
  }

  let tenantAccount: Awaited<ReturnType<IdentityRepository["getTenantAccount"]>>;
  let workspace: Awaited<ReturnType<IdentityRepository["resolveDefaultWorkspace"]>>;
  try {
    tenantAccount = await repository.getTenantAccount(args.tenantId);
    workspace = await repository.resolveDefaultWorkspace(args.tenantId);
  } catch (error) {
    return storageError(error);
  }
  if (!tenantAccount) return internalError("tenant account no longer exists");
  if (!workspace) return internalError("no workspace found for this tenant");

  // #514/#517: the tier that mints the key is `effectiveRole`, NOT a fixed
  // grant — and a suspended tenancy must yield a refusal, not a live `fg_…`
  // secret and not a session.
  let gatewayApiKey: string;
  try {
    gatewayApiKey = await session.provisionGatewayApiKey({
      workspaceId: workspace.id,
      projectId: workspace.projectId,
      tenantId: args.tenantId,
      userId: user.id,
      role: effectiveRole,
    });
  } catch (error) {
    return lifecycleError(error);
  }

  try {
    const issued = await session.issueSession({
      userId: user.id,
      email: args.email,
      tenantId: args.tenantId,
      role: effectiveRole,
    });
    return {
      status: 200,
      body: {
        access_token: issued.accessToken,
        refresh_token: issued.refreshToken,
        expires_in: issued.expiresIn,
        user: { id: user.id, email: args.email, display_name: user.displayName },
        tenant: { id: tenantAccount.id, name: tenantAccount.name, role: effectiveRole },
        gateway_api_key: gatewayApiKey,
      },
    };
  } catch (error) {
    return internalError(error instanceof Error ? error.message : "failed to issue a session");
  }
}
