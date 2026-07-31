/**
 * Per-user MCP OAuth/OIDC identity lifecycle and fail-closed dispatch
 * resolution.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/state_mcp_identity.rs`:
 * `start_mcp_oauth` (PKCE S256 + opaque state + OIDC nonce),
 * `complete_mcp_oauth` (single-use state, subject binding, generation CAS),
 * `mcp_identity_status`, `revoke_mcp_identity` (local revoke → best-effort
 * upstream revoke), and `resolve_mcp_identity` (the fail-closed dispatch seam
 * feeding `McpDispatchHeaders`).
 *
 * Load-bearing invariants preserved:
 *  - the raw `state` is NEVER stored; only its sha256 is the flow key;
 *  - a flow is single-use AND time-bounded (600 s);
 *  - the OIDC `sub` MUST equal the FerroGate user that started the flow, else
 *    `mcp_identity_subject_mismatch` (403);
 *  - the commit is refused when the actor's authorization generation moved
 *    during the flow (`mcp_oauth_authorization_changed`);
 *  - the PKCE verifier and both tokens are AEAD-sealed with AAD binding them to
 *    (flow/credential id, actor, server) so a row cannot be transplanted;
 *  - an unconnected / revoked / expired-and-unrefreshable identity FAILS the
 *    dispatch — it never falls back to an unauthenticated upstream call.
 */
import {
  credentialId,
  McpDispatchHeaders,
  type DispatchContext,
  type McpIdentityActor,
  type McpOauthConfig,
  type McpPorts,
  type McpServerConfig,
  type StoredMcpOauthCredential,
} from "../ports.js";

/** OAuth authorization flows live 10 minutes. */
export const OAUTH_FLOW_TTL_SECS = 600;
/** A minted `ferrogate_signed_jwt` identity lives 60 seconds. */
export const SIGNED_IDENTITY_TTL_SECS = 60;
/** Refresh a credential this many seconds before it actually expires. */
export const TOKEN_REFRESH_SKEW_SECS = 30;

/** Typed error mirroring `McpIdentityError` (status + stable code + message). */
export class McpIdentityError extends Error {
  override readonly name = "McpIdentityError";
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }

  static badRequest(code: string, message: string): McpIdentityError {
    return new McpIdentityError(400, code, message);
  }

  static unauthorized(code: string, message: string): McpIdentityError {
    return new McpIdentityError(401, code, message);
  }

  static forbidden(code: string, message: string): McpIdentityError {
    return new McpIdentityError(403, code, message);
  }

  static notFound(message: string): McpIdentityError {
    return new McpIdentityError(404, "mcp_identity_not_found", message);
  }

  static unavailable(code: string, message: string): McpIdentityError {
    return new McpIdentityError(503, code, message);
  }
}

/** `POST /v1/mcp/identity/{server}/authorize` response body. */
export interface McpOauthAuthorizeView {
  object: "mcp_oauth_authorization";
  server_name: string;
  authorize_url: string;
  state: string;
  expires_at_unix: number;
}

/** `GET|DELETE /v1/mcp/identity/{server}` and the callback response body. */
export interface McpIdentityStatusView {
  object: "mcp_identity";
  server_name: string;
  auth_type: string;
  connected: boolean;
  credential_source: string;
  subject: string | null;
  expires_at_unix: number | null;
  revoked_at_unix: number | null;
  last_refresh_outcome: string | null;
  last_revocation_outcome: string | null;
}

/** What one dispatch resolved to. Port of `McpIdentityResolution`. */
export interface McpIdentityResolution {
  headers: McpDispatchHeaders;
  credentialSource: string;
  subject?: string;
}

/** The (tenant, workspace, user) triple the caller's credential is scoped to. */
export function identityActor(context: DispatchContext): McpIdentityActor {
  const { organizationId, workspaceId, userId } = context.auth;
  if (organizationId === undefined || workspaceId === undefined || userId === undefined) {
    throw McpIdentityError.forbidden(
      "mcp_identity_actor_unresolved",
      "per-user MCP identity requires a tenant-, workspace-, and user-attributed credential",
    );
  }
  return { tenantId: organizationId, workspaceId, userId };
}

function requireServer(ports: McpPorts, serverName: string): McpServerConfig {
  const server = ports.upstreams.getServer(serverName);
  if (server === undefined) {
    throw McpIdentityError.notFound(`MCP server ${serverName} is not configured`);
  }
  return server;
}

function requireOauth(server: McpServerConfig): McpOauthConfig {
  if (server.oauth === undefined) {
    throw McpIdentityError.unavailable(
      "mcp_identity_provider_invalid",
      `MCP server ${server.name} has no OAuth configuration`,
    );
  }
  return server.oauth;
}

// ---------------------------------------------------------------------------
// POST /v1/mcp/identity/{server}/authorize
// ---------------------------------------------------------------------------

export async function startMcpOauth(
  ports: McpPorts,
  context: DispatchContext,
  serverName: string,
): Promise<McpOauthAuthorizeView> {
  const actor = identityActor(context);
  const server = requireServer(ports, serverName);
  if (server.authType !== "per_user_oauth") {
    throw McpIdentityError.badRequest(
      "mcp_identity_mode_mismatch",
      `MCP server ${serverName} does not use per_user_oauth`,
    );
  }
  const oauth = requireOauth(server);
  const discovery = await ports.oauth.discover(oauth);

  const verifier = randomUrlSafe(48);
  const challenge = base64UrlEncode(await sha256(new TextEncoder().encode(verifier)));
  const state = randomUrlSafe(32);
  // The raw state never touches storage — only its digest keys the flow, so a
  // storage read cannot forge a callback.
  const stateId = await sha256Hex(state);
  const oidcNonce = randomUrlSafe(24);

  const sealed = await ports.cipher.encrypt(
    new TextEncoder().encode(verifier),
    new TextEncoder().encode(flowAad(stateId, actor, serverName)),
  );
  const now = ports.now();
  const generation = await ports.credentials.authorizationGeneration(actor, serverName);
  await ports.credentials.beginOauthFlow({
    id: stateId,
    actor,
    serverName,
    pkceNonce: sealed.nonce,
    pkceCiphertext: sealed.ciphertext,
    oidcNonce,
    authorizationGeneration: generation,
    createdAtUnix: now,
    expiresAtUnix: now + OAUTH_FLOW_TTL_SECS,
  });

  const authorizeUrl = new URL(discovery.authorizationEndpoint);
  authorizeUrl.searchParams.append("response_type", "code");
  authorizeUrl.searchParams.append("client_id", oauth.clientId);
  authorizeUrl.searchParams.append("redirect_uri", oauth.redirectUri ?? "");
  authorizeUrl.searchParams.append("scope", oauth.scopes.join(" "));
  authorizeUrl.searchParams.append("state", state);
  authorizeUrl.searchParams.append("nonce", oidcNonce);
  authorizeUrl.searchParams.append("code_challenge", challenge);
  authorizeUrl.searchParams.append("code_challenge_method", "S256");

  return {
    object: "mcp_oauth_authorization",
    server_name: serverName,
    authorize_url: authorizeUrl.toString(),
    state,
    expires_at_unix: now + OAUTH_FLOW_TTL_SECS,
  };
}

// ---------------------------------------------------------------------------
// GET /v1/mcp/identity/callback
// ---------------------------------------------------------------------------

export async function completeMcpOauth(
  ports: McpPorts,
  params: { state: string; code: string; requestId: string; traceId?: string },
): Promise<McpIdentityStatusView> {
  if (params.state.trim().length === 0 || params.code.trim().length === 0) {
    throw McpIdentityError.badRequest(
      "mcp_oauth_callback_invalid",
      "OAuth callback requires code and state",
    );
  }
  const now = ports.now();
  const stateId = await sha256Hex(params.state);
  const flow = await ports.credentials.consumeOauthFlow(stateId, now);
  if (flow === undefined) {
    throw McpIdentityError.unauthorized(
      "mcp_oauth_state_invalid",
      "OAuth state is unknown, expired, or already used",
    );
  }
  const server = requireServer(ports, flow.serverName);
  if (server.authType !== "per_user_oauth") {
    throw McpIdentityError.badRequest(
      "mcp_identity_mode_mismatch",
      "MCP server identity mode changed during OAuth flow",
    );
  }
  const oauth = requireOauth(server);
  const discovery = await ports.oauth.discover(oauth);

  const verifierBytes = await ports.cipher.decrypt(
    flow.pkceNonce,
    flow.pkceCiphertext,
    new TextEncoder().encode(flowAad(stateId, flow.actor, flow.serverName)),
  );
  const codeVerifier = new TextDecoder().decode(verifierBytes);
  const clientSecret = await resolveClientSecret(ports, oauth);

  const token = await ports.oauth.exchangeAuthorizationCode(discovery, oauth, {
    code: params.code,
    codeVerifier,
    clientSecret,
  });
  if (token.tokenType.toLowerCase() !== "bearer" || token.accessToken.trim().length === 0) {
    throw McpIdentityError.unavailable(
      "mcp_identity_provider_invalid",
      "OIDC token endpoint did not return a usable bearer token",
    );
  }
  if (token.idToken === undefined) {
    throw McpIdentityError.unauthorized(
      "mcp_oidc_id_token_missing",
      "OIDC token response did not include id_token",
    );
  }
  const subject = await ports.oauth.validateIdToken(
    discovery,
    oauth,
    token.idToken,
    flow.oidcNonce,
  );
  // The provider's subject MUST be the FerroGate user that started the flow;
  // otherwise a stolen `code` would bind someone else's grant to this actor.
  if (subject !== flow.actor.userId) {
    throw McpIdentityError.forbidden(
      "mcp_identity_subject_mismatch",
      "OIDC subject does not match the FerroGate user that started this flow",
    );
  }

  const id = credentialId(flow.actor, flow.serverName);
  const aad = new TextEncoder().encode(credentialAad(id, flow.actor, flow.serverName));
  const access = await ports.cipher.encrypt(new TextEncoder().encode(token.accessToken), aad);
  const refresh =
    token.refreshToken === undefined
      ? undefined
      : await ports.cipher.encrypt(new TextEncoder().encode(token.refreshToken), aad);
  const expiresAtUnix = now + (token.expiresIn ?? 300);

  const credential: StoredMcpOauthCredential = {
    id,
    actor: flow.actor,
    serverName: flow.serverName,
    issuer: oauth.issuer,
    subject,
    tokenType: "Bearer",
    scopes: (token.scope ?? "").split(/\s+/).filter((scope) => scope.length > 0),
    accessTokenNonce: access.nonce,
    accessTokenCiphertext: access.ciphertext,
    expiresAtUnix,
    keyVersion: 1,
    version: 1,
    authorizationGeneration: flow.authorizationGeneration,
    createdAtUnix: now,
    updatedAtUnix: now,
    lastRefreshOutcome: "connected",
  };
  if (refresh !== undefined) {
    credential.refreshTokenNonce = refresh.nonce;
    credential.refreshTokenCiphertext = refresh.ciphertext;
  }

  const committed = await ports.credentials.commitOauthCallback(flow, credential);
  if (!committed) {
    throw McpIdentityError.forbidden(
      "mcp_oauth_authorization_changed",
      "MCP OAuth authorization changed before callback completion",
    );
  }

  ports.audit.record({
    request_id: params.requestId,
    ...(params.traceId === undefined ? {} : { trace_id: params.traceId }),
    tenant: {
      organization_id: flow.actor.tenantId,
      workspace_id: flow.actor.workspaceId,
      user_id: flow.actor.userId,
    },
    action: "mcp.identity.connect",
    target: `mcp:${flow.serverName}/subject:${flow.actor.userId}`,
    outcome: "connected",
    message: `server=${flow.serverName} workspace=${flow.actor.workspaceId} subject=${subject} source=per_user_oauth decision=allow`,
  });

  return {
    object: "mcp_identity",
    server_name: flow.serverName,
    auth_type: "per_user_oauth",
    connected: true,
    credential_source: "per_user_oauth",
    subject,
    expires_at_unix: expiresAtUnix,
    revoked_at_unix: null,
    last_refresh_outcome: "connected",
    last_revocation_outcome: null,
  };
}

// ---------------------------------------------------------------------------
// GET /v1/mcp/identity/{server}
// ---------------------------------------------------------------------------

export async function mcpIdentityStatus(
  ports: McpPorts,
  context: DispatchContext,
  serverName: string,
): Promise<McpIdentityStatusView> {
  const server = requireServer(ports, serverName);
  const actor = identityActor(context);
  const credential = await ports.credentials.getCredential(actor, serverName);
  return {
    object: "mcp_identity",
    server_name: serverName,
    auth_type: server.authType,
    connected: credential !== undefined && credential.revokedAtUnix === undefined,
    credential_source: server.authType,
    subject: credential?.subject ?? null,
    expires_at_unix: credential?.expiresAtUnix ?? null,
    revoked_at_unix: credential?.revokedAtUnix ?? null,
    last_refresh_outcome: credential?.lastRefreshOutcome ?? null,
    last_revocation_outcome: credential?.lastRevocationOutcome ?? null,
  };
}

// ---------------------------------------------------------------------------
// DELETE /v1/mcp/identity/{server}
// ---------------------------------------------------------------------------

export async function revokeMcpIdentity(
  ports: McpPorts,
  context: DispatchContext,
  serverName: string,
): Promise<McpIdentityStatusView> {
  const server = requireServer(ports, serverName);
  const actor = identityActor(context);
  const existing = await ports.credentials.getCredential(actor, serverName);
  if (existing === undefined || existing.revokedAtUnix !== undefined) {
    throw McpIdentityError.notFound("no MCP identity is connected for this subject");
  }
  const now = ports.now();
  // Local revocation lands FIRST and unconditionally: the grant must stop being
  // dispatchable even when the provider's revocation endpoint is unreachable.
  const revoked = await ports.credentials.revokeCredential(actor, serverName, now, "local_revoked");
  if (revoked === undefined) throw McpIdentityError.notFound("MCP identity is already revoked");
  ports.metrics.recordMcpIdentityRevocation();

  let outcome = "local_revoked";
  if (server.oauth !== undefined) {
    outcome = await bestEffortUpstreamRevoke(ports, server, actor, revoked, outcome);
  }
  await ports.credentials.updateRevocationOutcome(actor, serverName, outcome);

  return {
    object: "mcp_identity",
    server_name: serverName,
    auth_type: server.authType,
    connected: false,
    credential_source: server.authType,
    subject: revoked.subject,
    expires_at_unix: revoked.expiresAtUnix,
    revoked_at_unix: now,
    last_refresh_outcome: revoked.lastRefreshOutcome ?? null,
    last_revocation_outcome: outcome,
  };
}

async function bestEffortUpstreamRevoke(
  ports: McpPorts,
  server: McpServerConfig,
  actor: McpIdentityActor,
  credential: StoredMcpOauthCredential,
  fallback: string,
): Promise<string> {
  const oauth = server.oauth;
  if (oauth === undefined) return fallback;
  try {
    const discovery = await ports.oauth.discover(oauth);
    if (discovery.revocationEndpoint === undefined) return fallback;
    const aad = new TextEncoder().encode(
      credentialAad(credential.id, actor, credential.serverName),
    );
    let token: string | undefined;
    if (credential.refreshTokenNonce && credential.refreshTokenCiphertext) {
      token = new TextDecoder().decode(
        await ports.cipher.decrypt(
          credential.refreshTokenNonce,
          credential.refreshTokenCiphertext,
          aad,
        ),
      );
    } else {
      token = new TextDecoder().decode(
        await ports.cipher.decrypt(
          credential.accessTokenNonce,
          credential.accessTokenCiphertext,
          aad,
        ),
      );
    }
    const revoked = await ports.oauth.revoke(discovery, oauth, token);
    return revoked ? "upstream_revoked" : "upstream_revocation_failed";
  } catch {
    return "upstream_revocation_failed";
  }
}

// ---------------------------------------------------------------------------
// Dispatch-time resolution (fail closed)
// ---------------------------------------------------------------------------

/**
 * Resolve the per-request identity for an upstream. FAILS CLOSED: any mode that
 * cannot produce a credential throws rather than dispatching unauthenticated.
 */
export async function resolveMcpIdentity(
  ports: McpPorts,
  context: DispatchContext,
  serverName: string,
): Promise<McpIdentityResolution> {
  const server = requireServer(ports, serverName);
  switch (server.authType) {
    case "none":
    case "shared_headers":
      // Static headers already live on the upstream config and are applied by
      // the transport; there is no per-request identity to add.
      return { headers: McpDispatchHeaders.empty(), credentialSource: server.authType };

    case "per_user_oauth": {
      const actor = identityActor(context);
      let credential = await ports.credentials.getCredential(actor, serverName);
      if (credential === undefined || credential.revokedAtUnix !== undefined) {
        throw McpIdentityError.unauthorized(
          "mcp_identity_not_connected",
          "per-user MCP identity is not connected",
        );
      }
      if (credential.expiresAtUnix <= ports.now() + TOKEN_REFRESH_SKEW_SECS) {
        credential = await refreshCredential(ports, server, actor, credential);
      }
      const aad = new TextEncoder().encode(credentialAad(credential.id, actor, serverName));
      const token = new TextDecoder().decode(
        await ports.cipher.decrypt(
          credential.accessTokenNonce,
          credential.accessTokenCiphertext,
          aad,
        ),
      );
      return {
        headers: McpDispatchHeaders.bearer(token),
        credentialSource: "per_user_oauth",
        subject: credential.subject,
      };
    }

    case "original_bearer": {
      const actor = identityActor(context);
      const token = context.originalBearer?.trim();
      if (token === undefined || token.length === 0) {
        throw McpIdentityError.unauthorized(
          "mcp_original_bearer_missing",
          "validated original bearer token is required",
        );
      }
      const oauth = requireOauth(server);
      const discovery = await ports.oauth.discover(oauth);
      const subject = await ports.oauth.validateIdToken(discovery, oauth, token);
      if (subject !== actor.userId) {
        throw McpIdentityError.forbidden(
          "mcp_identity_subject_mismatch",
          "original bearer subject does not match authenticated user",
        );
      }
      return {
        headers: McpDispatchHeaders.bearer(token),
        credentialSource: "original_bearer",
        subject,
      };
    }

    case "ferrogate_signed_jwt": {
      const actor = identityActor(context);
      const now = ports.now();
      const token = await signIdentityJwt(ports, {
        sub: actor.userId,
        aud: server.signedJwtAudience ?? "",
        tenant_id: actor.tenantId,
        workspace_id: actor.workspaceId,
        server_name: serverName,
        iat: now,
        exp: now + SIGNED_IDENTITY_TTL_SECS,
        jti: randomUrlSafe(18),
      });
      return {
        headers: McpDispatchHeaders.bearer(token),
        credentialSource: "ferrogate_signed_jwt",
        subject: actor.userId,
      };
    }

    case "oauth":
    case "per_user_headers":
      // Config validation accepts these modes; the runtime has no
      // implementation, so refuse rather than dispatch with no identity.
      throw McpIdentityError.unavailable(
        "mcp_identity_mode_unsupported",
        "MCP identity mode passed validation without a runtime implementation",
      );
  }
}

async function refreshCredential(
  ports: McpPorts,
  server: McpServerConfig,
  actor: McpIdentityActor,
  credential: StoredMcpOauthCredential,
): Promise<StoredMcpOauthCredential> {
  const oauth = requireOauth(server);
  if (
    credential.refreshTokenNonce === undefined ||
    credential.refreshTokenCiphertext === undefined
  ) {
    throw McpIdentityError.unauthorized(
      "mcp_identity_expired",
      "per-user MCP identity expired and carries no refresh token",
    );
  }
  const aad = new TextEncoder().encode(credentialAad(credential.id, actor, credential.serverName));
  const refreshToken = new TextDecoder().decode(
    await ports.cipher.decrypt(
      credential.refreshTokenNonce,
      credential.refreshTokenCiphertext,
      aad,
    ),
  );
  const discovery = await ports.oauth.discover(oauth);
  const clientSecret = await resolveClientSecret(ports, oauth);
  let token;
  try {
    token = await ports.oauth.refresh(discovery, oauth, { refreshToken, clientSecret });
  } catch (cause) {
    throw McpIdentityError.unauthorized(
      "mcp_identity_refresh_failed",
      `per-user MCP identity refresh failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const now = ports.now();
  const access = await ports.cipher.encrypt(new TextEncoder().encode(token.accessToken), aad);
  const refreshed: StoredMcpOauthCredential = {
    ...credential,
    accessTokenNonce: access.nonce,
    accessTokenCiphertext: access.ciphertext,
    expiresAtUnix: now + (token.expiresIn ?? 300),
    version: credential.version + 1,
    updatedAtUnix: now,
    lastRefreshOutcome: "refreshed",
  };
  if (token.refreshToken !== undefined) {
    const rotated = await ports.cipher.encrypt(new TextEncoder().encode(token.refreshToken), aad);
    refreshed.refreshTokenNonce = rotated.nonce;
    refreshed.refreshTokenCiphertext = rotated.ciphertext;
  }
  await ports.credentials.putCredential(refreshed);
  return refreshed;
}

/**
 * Materialize an upstream's `client_secret_ref` through the bound secret seam
 * ({@link McpPorts.secrets}, which `resolvePorts` binds to
 * `@ferrogate/secrets`' registry).
 *
 * Two distinct outcomes, both reported as `mcp_identity_secret_unavailable`
 * because both leave the exchange unable to proceed, but with different text:
 *
 *  - `undefined` — the reference parsed and named nothing that is bound
 *    ("not configured").
 *  - a THROW — a genuine backend failure: an unparseable reference, an
 *    ambiguous `cf://` name the resolver refuses to guess at, a `vault://`
 *    reference with no `VAULT_ADDR`/`VAULT_TOKEN`. The resolver's own message
 *    is the operator's only diagnostic, so it is carried through rather than
 *    collapsed into a 500. Resolver messages name variables and references,
 *    never values.
 */
async function resolveClientSecret(ports: McpPorts, oauth: McpOauthConfig): Promise<string> {
  if (oauth.clientSecretRef === undefined) return "";
  let resolved: string | undefined;
  try {
    resolved = await ports.secrets.resolve(oauth.clientSecretRef);
  } catch (cause) {
    throw McpIdentityError.unavailable(
      "mcp_identity_secret_unavailable",
      `MCP OAuth client secret ${oauth.clientSecretRef} could not be resolved: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }
  if (resolved === undefined) {
    throw McpIdentityError.unavailable(
      "mcp_identity_secret_unavailable",
      `MCP OAuth client secret ${oauth.clientSecretRef} could not be resolved`,
    );
  }
  return resolved;
}

/** HS256 JWT signed with the domain-separated identity key. */
async function signIdentityJwt(
  ports: McpPorts,
  claims: Record<string, string | number>,
): Promise<string> {
  const header = base64UrlEncodeString(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncodeString(JSON.stringify({ iss: "ferrogate", ...claims }));
  const signingInput = `${header}.${body}`;
  const key = await ports.cipher.signingKey();
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

// ---------------------------------------------------------------------------
// AAD binding + crypto helpers
// ---------------------------------------------------------------------------

/** Binds a sealed PKCE verifier to (state digest, actor, server). */
export function flowAad(stateId: string, actor: McpIdentityActor, serverName: string): string {
  return `mcp-oauth-flow:v1:${stateId}:${actor.tenantId}:${actor.workspaceId}:${actor.userId}:${serverName}`;
}

/** Binds sealed tokens to (credential id, actor, server). */
export function credentialAad(id: string, actor: McpIdentityActor, serverName: string): string {
  return `mcp-oauth-credential:v1:${id}:${actor.tenantId}:${actor.workspaceId}:${actor.userId}:${serverName}`;
}

export function randomUrlSafe(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await sha256(new TextEncoder().encode(value));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(new TextEncoder().encode(value));
}
