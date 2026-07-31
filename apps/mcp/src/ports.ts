/**
 * Narrow local interfaces (dependency inversion) for everything `apps/mcp`
 * needs from the wave-2 library packages, plus in-memory defaults so the app is
 * runnable and fully testable on its own.
 *
 * The app codes against THESE types, never against `@ferrogate/policy`,
 * `@ferrogate/storage`, `@ferrogate/secrets`, … internals. When those packages
 * land, bind a real implementation in {@link resolvePorts} — nothing else in
 * this app changes.
 *
 * PORT-TODO(inventory-edge-control §MCP): PLATFORM LIMIT — stdio MCP upstreams
 * are impossible in a Worker. The Rust host
 * (`crates/ferrogate-mcp/src/stdio_client.rs`) spawns a child process per
 * upstream and owns `dispatch_cleanup_handle` (timeout → kill the stdio child,
 * mark the session unavailable). workerd has no `fork`/`exec`, no pipes and no
 * process table, so there is nothing to spawn and nothing to kill.
 *
 * IMPLEMENTED INSTEAD: `transport: "stdio"` is accepted by config (so the
 * operator's catalog round-trips and the misconfiguration is VISIBLE) and
 * REFUSED at dispatch with `mcp_server_unavailable` rather than silently
 * behaving like HTTP. Such upstreams must move to a Container /
 * `@cloudflare/sandbox` or stay off-CF. See `src/transport.ts` for the full
 * note and the tests that pin it.
 */
import type { JsonValue } from "@ferrogate/core";

// `./durable.js` imports the TYPES and `webCryptoIdentityCipher` back out of
// this module. The cycle is safe because neither side touches the other at
// module-evaluation time — every reference is inside a function body.
import { DurableCredentialStore, decodeIdentityKey, identityCipherFrom } from "./durable.js";
import type { ParsedToolDef } from "./jsonrpc.js";
import { DurableOauthFlowStore, type McpOauthFlowClaim } from "./oauth-flow.js";

// ---------------------------------------------------------------------------
// Upstream MCP server configuration (port of `ferrogate-mcp/src/config.rs`)
// ---------------------------------------------------------------------------

/** Transports the Rust `McpTransport` enum names. */
export type McpTransport = "streamable_http" | "sse" | "stdio";

/** Per-upstream identity mode. Port of `McpAuthType`. */
export type McpAuthType =
  | "none"
  | "shared_headers"
  | "oauth"
  | "per_user_oauth"
  | "per_user_headers"
  | "original_bearer"
  | "ferrogate_signed_jwt";

/** OAuth/OIDC configuration for a per-user (or original-bearer) upstream. */
export interface McpOauthConfig {
  issuer: string;
  clientId: string;
  /** Reference resolved through the secrets seam (e.g. `env://VAR`). */
  clientSecretRef?: string;
  redirectUri?: string;
  scopes: string[];
  audience?: string;
}

/** One configured upstream MCP server. */
export interface McpServerConfig {
  name: string;
  transport: McpTransport;
  url?: string;
  authType: McpAuthType;
  /** Deny-by-default execution allowlist. Empty ⇒ nothing is listed or callable. */
  toolsToExecute: string[];
  /** Subset of {@link toolsToExecute} that may run without an approval. */
  toolsToAutoExecute: string[];
  /** Static headers merged into every dispatch (`shared_headers`). */
  headers?: Record<string, string>;
  oauth?: McpOauthConfig;
  signedJwtAudience?: string;
  timeoutMs: number;
}

/** Tool as the host exposes it: namespaced `{server}-{remote}`. */
export interface McpTool {
  name: string;
  serverName: string;
  remoteName: string;
  description?: string;
  inputSchema: JsonValue;
  autoExecute: boolean;
}

// ---------------------------------------------------------------------------
// Per-request identity headers (port of `McpDispatchHeaders`)
// ---------------------------------------------------------------------------

/**
 * The per-request identity carried into an upstream `call_tool`. This is how a
 * per-user OAuth grant / signed identity / original bearer reaches the
 * upstream. Rust redacts its `Debug`; this class redacts `toString`/`toJSON` so
 * a stray log line can never spill the token.
 */
export class McpDispatchHeaders {
  readonly #entries: ReadonlyArray<readonly [string, string]>;

  private constructor(entries: ReadonlyArray<readonly [string, string]>) {
    this.#entries = entries;
  }

  static empty(): McpDispatchHeaders {
    return new McpDispatchHeaders([]);
  }

  /** Throws when the token cannot be a valid HTTP header value. */
  static bearer(token: string): McpDispatchHeaders {
    const value = `Bearer ${token}`;
    if (!/^[\t\x20-\x7e\x80-\xff]*$/.test(value)) {
      throw new Error("MCP bearer token is not a valid HTTP header value");
    }
    return new McpDispatchHeaders([["Authorization", value]]);
  }

  static from(entries: ReadonlyArray<readonly [string, string]>): McpDispatchHeaders {
    return new McpDispatchHeaders([...entries]);
  }

  entries(): ReadonlyArray<readonly [string, string]> {
    return this.#entries;
  }

  get count(): number {
    return this.#entries.length;
  }

  applyTo(headers: Headers): void {
    for (const [name, value] of this.#entries) headers.set(name, value);
  }

  toString(): string {
    return `McpDispatchHeaders { count: ${this.#entries.length}, values: <redacted> }`;
  }

  toJSON(): { count: number; values: string } {
    return { count: this.#entries.length, values: "<redacted>" };
  }
}

// ---------------------------------------------------------------------------
// Dispatch context — the correlation chain (#522)
// ---------------------------------------------------------------------------

/** Resolved caller identity for one MCP request. */
export interface AuthContext {
  apiKeyId?: string;
  organizationId?: string;
  workspaceId?: string;
  projectId?: string;
  teamId?: string;
  userId?: string;
  scopes: readonly string[];
  /** RBAC permission keys bound to the caller (e.g. `mcp.execute`). */
  permissions: readonly string[];
  /** A declared platform operator names no tenant and is entitlement-exempt (#515). */
  platformOperator: boolean;
}

/** Narrowing helper: a JSON object (not `null`, not an array). */
export function isJsonObjectValue(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasScope(auth: AuthContext, scope: string): boolean {
  return auth.scopes.includes(scope) || auth.scopes.includes("*");
}

export function tenantContext(auth: AuthContext): Record<string, string | undefined> {
  return {
    organization_id: auth.organizationId,
    team_id: auth.teamId,
    project_id: auth.projectId,
    workspace_id: auth.workspaceId,
    user_id: auth.userId,
    api_key_id: auth.apiKeyId,
  };
}

/**
 * Everything one governed MCP dispatch needs to stay joinable. `agentRunId` is
 * the load-bearing field: it is threaded from the validated
 * `x-ferrogate-agent-run-id` header through routing, the governed tool
 * chokepoint, and out onto every audit row and the upstream call itself.
 * `undefined` means the caller declared nothing — NEVER fabricate one.
 */
export interface DispatchContext {
  requestId: string;
  traceId?: string;
  agentRunId?: string;
  auth: AuthContext;
  /** Validated original bearer (`x-ferrogate-mcp-bearer`) for `original_bearer` upstreams. */
  originalBearer?: string;
  skill?: { id: string; version: string };
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** Port of `AdminAuditEventDraft`, trimmed to the fields this app stamps. */
export interface AuditEvent {
  request_id: string;
  trace_id?: string;
  /** #522: joins this row into the caller's correlation chain. */
  agent_run_id?: string;
  actor_api_key_id?: string;
  tenant: Record<string, string | undefined>;
  action: string;
  target: string;
  outcome: string;
  message: string;
}

export interface AuditSinkPort {
  record(event: AuditEvent): void;
  /** Recorded rows, newest last. Test/debug affordance; a real sink may return []. */
  events(): readonly AuditEvent[];
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export interface MetricsPort {
  /** Bounded operation/tool labels only — client metadata never becomes a label. */
  recordMcpMethodRequest(method: string, name: string): void;
  /** #522: a governed action arrived with no declared run id, per tenant + surface. */
  recordUnjoinableAction(tenantKey: string, surface: string): void;
  recordMcpIdentityResolution(allowed: boolean): void;
  recordMcpIdentityRevocation(): void;
}

// ---------------------------------------------------------------------------
// Auth + entitlement
// ---------------------------------------------------------------------------

export interface AuthError {
  status: number;
  code: string;
  message: string;
}

export interface AuthPort {
  /** Resolve a bearer credential and enforce `requiredScope`. */
  authenticate(headers: Headers, requiredScope: string): Promise<AuthContext | AuthError>;
}

export function isAuthError(value: AuthContext | AuthError): value is AuthError {
  return typeof (value as AuthError).status === "number";
}

/** Which governed backend a tool execution runs on. Port of `ToolExecuteBackend`. */
export type ToolExecuteBackend = "mcp" | "builtin";

export interface EntitlementPort {
  /**
   * Plan/RBAC gate for tool execution (`tool_execution_entitlement_denial`).
   * `undefined` ⇒ allowed. The `builtin` backend carries no plan flag.
   */
  toolExecutionDenial(
    auth: AuthContext,
    backend: ToolExecuteBackend,
  ): Promise<{ code: string; message: string } | undefined>;
}

// ---------------------------------------------------------------------------
// Upstream MCP servers
// ---------------------------------------------------------------------------

/** Port of `McpExecutionError`'s code taxonomy. */
export type McpExecutionErrorCode =
  | "tool_denied"
  | "tool_not_found"
  | "mcp_server_unavailable"
  | "mcp_upstream_unauthorized"
  | "tool_execution_failed";

export class McpExecutionError extends Error {
  override readonly name = "McpExecutionError";
  readonly code: McpExecutionErrorCode;

  constructor(code: McpExecutionErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface McpUpstreamPort {
  listServers(): readonly McpServerConfig[];
  getServer(name: string): McpServerConfig | undefined;
  /** Namespaced, allowlisted tools visible to this caller. */
  listTools(): Promise<readonly McpTool[]>;
  toolByName(name: string): Promise<McpTool | undefined>;
  /**
   * Execute an allowlisted upstream tool. `identity` carries the resolved
   * per-request grant; `context` carries the correlation chain so an upstream
   * adapter (and any recorder behind it) can stamp `agentRunId`.
   */
  callTool(
    tool: McpTool,
    args: JsonValue,
    identity: McpDispatchHeaders,
    context: DispatchContext,
  ): Promise<{ content: JsonValue; isError: boolean }>;
}

// ---------------------------------------------------------------------------
// Governance seams the tool chokepoint runs (guardrails / approval / assets)
// ---------------------------------------------------------------------------

/** Managed-action guardrail verdict. Port of the `#200`/`#204` decision shape. */
export interface GuardrailVerdict {
  action: "allow" | "block" | "quarantine" | "redact" | "withhold";
  /** Replacement payload when the action rewrites rather than refuses. */
  payload?: JsonValue;
  reason?: string;
}

export interface GuardrailsPort {
  /** Runs BEFORE execution: may block or quarantine the arguments. */
  inspectInput(
    context: DispatchContext,
    toolName: string,
    args: JsonValue,
  ): Promise<GuardrailVerdict>;
  /** Runs AFTER execution: may redact or withhold the result. */
  inspectOutput(
    context: DispatchContext,
    toolName: string,
    content: JsonValue,
  ): Promise<GuardrailVerdict>;
}

export interface ApprovalPort {
  /**
   * Gate an execution that is not `auto_execute`. `undefined` ⇒ approved.
   * A pending/denied approval short-circuits the call with `tool_denied`.
   */
  require(
    context: DispatchContext,
    tool: McpTool,
    args: JsonValue,
  ): Promise<{ code: string; message: string } | undefined>;
}

/** A hosted asset exposed as an MCP resource (`asset://{type}/{name}/{version}`). */
export interface StoredAsset {
  assetType: string;
  name: string;
  version: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  /** #366: pending/quarantined assets are withheld from listing AND read. */
  downloadable: boolean;
}

export type AssetReadFailure =
  | { kind: "not_found" }
  | { kind: "integrity" }
  | { kind: "too_large"; message: string }
  | { kind: "overloaded"; message: string }
  | { kind: "bucket_unavailable"; message: string }
  | { kind: "storage"; message: string };

export interface AssetReaderPort {
  list(tenantId: string): Promise<readonly StoredAsset[]>;
  read(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<
    { ok: true; asset: StoredAsset; content: Uint8Array } | { ok: false; error: AssetReadFailure }
  >;
}

/**
 * Pass-through guardrails — a STUB, and the most security-relevant one left in
 * this Worker.
 *
 * PORT-TODO(inventory-edge-control §MCP): NOT a platform limit. It is a
 * deferral, and the thing it is waiting for now exists: `@ferrogate/guardrails`
 * is complete and its deterministic detector runs in workerd today.
 * `apps/agent-runtime/src/ports.ts::deterministicGuardrailPort` is a working
 * reference for exactly this binding — build a `GuardrailEnvelope` with
 * `envelopeFromText`, call `DeterministicDetector.evaluate` with an ABSOLUTE
 * deadline (`Date.now() + budget`, not the budget itself), and FAIL CLOSED on a
 * detector error.
 *
 * Until that lands this class allows everything, which means MCP tool
 * arguments and tool results are currently unscanned. That is a real gap, not a
 * cosmetic one; it is named here rather than hidden behind a plausible name.
 */
export class AllowAllGuardrails implements GuardrailsPort {
  // eslint-disable-next-line @typescript-eslint/require-await
  async inspectInput(): Promise<GuardrailVerdict> {
    return { action: "allow" };
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async inspectOutput(): Promise<GuardrailVerdict> {
    return { action: "allow" };
  }
}

/**
 * Approves anything already allowlisted.
 *
 * PORT-TODO(inventory-edge-control §MCP): NOT a platform limit — a deferral on
 * ANOTHER APP. The human-approval queue is control-plane state
 * (`apps/control-plane`), so binding it means a `[[services]]` service binding
 * or a shared D1 read, neither of which this Worker can create unilaterally.
 * Note the standing behavior: the deny-by-default `toolsToExecute` allowlist in
 * `src/tools.ts` is enforced INDEPENDENTLY of this port, so an un-allowlisted
 * tool is still refused — what is missing is the interactive step-up, not the
 * allowlist.
 */
export class AutoApproval implements ApprovalPort {
  // eslint-disable-next-line @typescript-eslint/require-await
  async require(): Promise<undefined> {
    return undefined;
  }
}

/**
 * In-memory asset catalog.
 *
 * PORT-TODO(inventory-edge-control §MCP): NOT a platform limit — CF has both
 * primitives this needs (R2 for the bytes, D1 for the catalog rows). It is a
 * deferral pending `@ferrogate/storage`'s asset surface. CONSEQUENCE while it
 * stands: assets do not survive an isolate recycle, so this is usable for the
 * dev bundle and not for a deployment.
 */
export class InMemoryAssets implements AssetReaderPort {
  readonly #assets = new Map<string, { asset: StoredAsset; content: Uint8Array }>();

  seed(tenantId: string, asset: StoredAsset, content: Uint8Array): this {
    this.#assets.set(assetKey(tenantId, asset.assetType, asset.name, asset.version), {
      asset,
      content,
    });
    return this;
  }

  clear(): void {
    this.#assets.clear();
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async list(tenantId: string): Promise<readonly StoredAsset[]> {
    const prefix = `${tenantId} `;
    return [...this.#assets.entries()]
      .filter(([key]) => key.startsWith(prefix))
      .map(([, entry]) => entry.asset);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async read(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<
    { ok: true; asset: StoredAsset; content: Uint8Array } | { ok: false; error: AssetReadFailure }
  > {
    const entry = this.#assets.get(assetKey(tenantId, assetType, name, version));
    // #366: an undownloadable (pending / quarantined) asset is indistinguishable
    // from a missing one at the read chokepoint — never a distinct signal.
    if (entry === undefined || !entry.asset.downloadable)
      return { ok: false, error: { kind: "not_found" } };
    return { ok: true, asset: entry.asset, content: entry.content };
  }
}

function assetKey(tenantId: string, assetType: string, name: string, version: string): string {
  return `${tenantId} ${assetType} ${name} ${version}`;
}

// ---------------------------------------------------------------------------
// Per-user MCP identity storage (port of `ferrogate-storage::McpCredentialRepository`)
// ---------------------------------------------------------------------------

/** The (tenant, workspace, user) triple an identity belongs to. */
export interface McpIdentityActor {
  tenantId: string;
  workspaceId: string;
  userId: string;
}

/** In-flight OAuth authorization. Port of `StoredMcpOauthFlow`. */
export interface StoredMcpOauthFlow {
  /** sha256 hex of the opaque `state` — the raw state is never stored. */
  id: string;
  actor: McpIdentityActor;
  serverName: string;
  /** AEAD-sealed PKCE verifier. */
  pkceNonce: Uint8Array;
  pkceCiphertext: Uint8Array;
  oidcNonce: string;
  authorizationGeneration: number;
  createdAtUnix: number;
  expiresAtUnix: number;
  consumedAtUnix?: number;
}

/** A stored per-user grant. Port of `StoredMcpOauthCredential`. */
export interface StoredMcpOauthCredential {
  id: string;
  actor: McpIdentityActor;
  serverName: string;
  issuer: string;
  subject: string;
  tokenType: string;
  scopes: string[];
  accessTokenNonce: Uint8Array;
  accessTokenCiphertext: Uint8Array;
  refreshTokenNonce?: Uint8Array;
  refreshTokenCiphertext?: Uint8Array;
  expiresAtUnix: number;
  keyVersion: number;
  version: number;
  authorizationGeneration: number;
  createdAtUnix: number;
  updatedAtUnix: number;
  revokedAtUnix?: number;
  lastRefreshOutcome?: string;
  lastRevocationOutcome?: string;
}

export interface McpCredentialStorePort {
  beginOauthFlow(flow: StoredMcpOauthFlow): Promise<void>;
  /** Single-use: returns the flow and marks it consumed, or `undefined`. */
  consumeOauthFlow(stateId: string, nowUnix: number): Promise<StoredMcpOauthFlow | undefined>;
  /**
   * Commit the callback grant. Returns `false` when the actor's authorization
   * generation moved during the flow (`mcp_oauth_authorization_changed`).
   */
  commitOauthCallback(
    flow: StoredMcpOauthFlow,
    credential: StoredMcpOauthCredential,
  ): Promise<boolean>;
  getCredential(
    actor: McpIdentityActor,
    serverName: string,
  ): Promise<StoredMcpOauthCredential | undefined>;
  putCredential(credential: StoredMcpOauthCredential): Promise<void>;
  revokeCredential(
    actor: McpIdentityActor,
    serverName: string,
    nowUnix: number,
    outcome: string,
  ): Promise<StoredMcpOauthCredential | undefined>;
  updateRevocationOutcome(
    actor: McpIdentityActor,
    serverName: string,
    outcome: string,
  ): Promise<void>;
  /** Current authorization generation for the actor (bumped on access change). */
  authorizationGeneration(actor: McpIdentityActor, serverName: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// OAuth / OIDC provider seam
// ---------------------------------------------------------------------------

export interface OidcDiscovery {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  revocationEndpoint?: string;
}

export interface OauthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn?: number;
  scope?: string;
  idToken?: string;
}

export interface OauthProviderPort {
  discover(oauth: McpOauthConfig): Promise<OidcDiscovery>;
  exchangeAuthorizationCode(
    discovery: OidcDiscovery,
    oauth: McpOauthConfig,
    params: { code: string; codeVerifier: string; clientSecret: string },
  ): Promise<OauthTokenResponse>;
  refresh(
    discovery: OidcDiscovery,
    oauth: McpOauthConfig,
    params: { refreshToken: string; clientSecret: string },
  ): Promise<OauthTokenResponse>;
  /** Returns the validated `sub`. Rejects on bad signature / issuer / aud / nonce. */
  validateIdToken(
    discovery: OidcDiscovery,
    oauth: McpOauthConfig,
    idToken: string,
    expectedNonce?: string,
  ): Promise<string>;
  revoke(discovery: OidcDiscovery, oauth: McpOauthConfig, token: string): Promise<boolean>;
}

/** Resolves `client_secret_ref` through the secrets seam. */
export interface SecretResolverPort {
  resolve(reference: string): Promise<string | undefined>;
}

/** Envelope encryption for stored credentials (`FERROGATE_MCP_IDENTITY_KEY`). */
export interface IdentityCipherPort {
  encrypt(
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }>;
  decrypt(nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  /** Domain-separated HMAC key for `ferrogate_signed_jwt` identities. */
  signingKey(): Promise<CryptoKey>;
}

// ---------------------------------------------------------------------------
// The port bundle
// ---------------------------------------------------------------------------

export interface McpPorts {
  auth: AuthPort;
  entitlements: EntitlementPort;
  upstreams: McpUpstreamPort;
  guardrails: GuardrailsPort;
  approvals: ApprovalPort;
  assets: AssetReaderPort;
  credentials: McpCredentialStorePort;
  oauth: OauthProviderPort;
  secrets: SecretResolverPort;
  cipher: IdentityCipherPort;
  audit: AuditSinkPort;
  metrics: MetricsPort;
  now(): number;
}

// ---------------------------------------------------------------------------
// In-memory defaults
// ---------------------------------------------------------------------------

export class InMemoryAuditSink implements AuditSinkPort {
  readonly #events: AuditEvent[] = [];

  record(event: AuditEvent): void {
    this.#events.push(event);
  }

  events(): readonly AuditEvent[] {
    return this.#events;
  }

  clear(): void {
    this.#events.length = 0;
  }
}

export class InMemoryMetrics implements MetricsPort {
  readonly methodRequests: Array<{ method: string; name: string }> = [];
  readonly unjoinableActions: Array<{ tenantKey: string; surface: string }> = [];
  readonly identityResolutions: boolean[] = [];
  identityRevocations = 0;

  recordMcpMethodRequest(method: string, name: string): void {
    this.methodRequests.push({ method, name });
  }

  recordUnjoinableAction(tenantKey: string, surface: string): void {
    this.unjoinableActions.push({ tenantKey, surface });
  }

  recordMcpIdentityResolution(allowed: boolean): void {
    this.identityResolutions.push(allowed);
  }

  recordMcpIdentityRevocation(): void {
    this.identityRevocations += 1;
  }

  clear(): void {
    this.methodRequests.length = 0;
    this.unjoinableActions.length = 0;
    this.identityResolutions.length = 0;
    this.identityRevocations = 0;
  }
}

/**
 * A static API-key table. This is a DEV/TEST implementation only — it is wired
 * only when the app is explicitly running with in-memory ports (see
 * {@link resolvePorts}); otherwise the app fails closed.
 */
export class InMemoryAuth implements AuthPort {
  readonly #keys = new Map<string, AuthContext>();

  register(token: string, auth: AuthContext): this {
    this.#keys.set(token, auth);
    return this;
  }

  clear(): void {
    this.#keys.clear();
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async authenticate(headers: Headers, requiredScope: string): Promise<AuthContext | AuthError> {
    const header = headers.get("authorization");
    if (header === null || !/^Bearer\s+/i.test(header)) {
      return {
        status: 401,
        code: "unauthenticated",
        message: "a Bearer API key is required",
      };
    }
    const token = header.replace(/^Bearer\s+/i, "").trim();
    const auth = this.#keys.get(token);
    if (auth === undefined) {
      return { status: 401, code: "invalid_api_key", message: "API key is not recognized" };
    }
    if (!hasScope(auth, requiredScope)) {
      return {
        status: 403,
        code: "insufficient_scope",
        message: `this credential is missing the ${requiredScope} scope`,
      };
    }
    return auth;
  }
}

/** Denies everything with a 503 — the fail-closed default when no port is bound. */
export class UnboundAuth implements AuthPort {
  // eslint-disable-next-line @typescript-eslint/require-await
  async authenticate(): Promise<AuthError> {
    return {
      status: 503,
      code: "mcp_auth_unavailable",
      message: "no authentication provider is bound to this Worker",
    };
  }
}

export class InMemoryEntitlements implements EntitlementPort {
  /** Tenants whose plan/roles do NOT permit MCP tool execution. */
  readonly deniedTenants = new Set<string>();

  // eslint-disable-next-line @typescript-eslint/require-await
  async toolExecutionDenial(
    auth: AuthContext,
    backend: ToolExecuteBackend,
  ): Promise<{ code: string; message: string } | undefined> {
    // Built-in tools carry no plan feature flag: their authz is enforced inside
    // the tool itself, so there is no separate entitlement to deny here.
    if (backend === "builtin") return undefined;
    // #515: only a declared platform operator is exempt. A credential that
    // merely never named a tenant is NOT exempt.
    if (auth.organizationId === undefined) return undefined;
    if (!this.deniedTenants.has(auth.organizationId)) return undefined;
    if (auth.permissions.includes("mcp.execute")) return undefined;
    return {
      code: "mcp_tools_disabled",
      message:
        "the tenant's plan does not enable MCP tool execution and no bound role grants the mcp.execute permission",
    };
  }
}

/**
 * An in-memory MCP host: configured upstreams plus a per-server tool handler.
 * Real deployments replace the handler with the Streamable-HTTP/SSE client in
 * `transport.ts` (see {@link HttpMcpUpstreams} there).
 */
export class InMemoryUpstreams implements McpUpstreamPort {
  readonly #servers = new Map<string, McpServerConfig>();
  readonly #tools = new Map<string, ParsedToolDef[]>();
  readonly #handlers = new Map<
    string,
    (
      tool: McpTool,
      args: JsonValue,
      identity: McpDispatchHeaders,
      context: DispatchContext,
    ) => Promise<{ content: JsonValue; isError: boolean }>
  >();

  register(
    config: McpServerConfig,
    tools: ParsedToolDef[],
    handler?: (
      tool: McpTool,
      args: JsonValue,
      identity: McpDispatchHeaders,
      context: DispatchContext,
    ) => Promise<{ content: JsonValue; isError: boolean }>,
  ): this {
    this.#servers.set(config.name, config);
    this.#tools.set(config.name, tools);
    if (handler) this.#handlers.set(config.name, handler);
    return this;
  }

  clear(): void {
    this.#servers.clear();
    this.#tools.clear();
    this.#handlers.clear();
  }

  listServers(): readonly McpServerConfig[] {
    return [...this.#servers.values()];
  }

  getServer(name: string): McpServerConfig | undefined {
    return this.#servers.get(name);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async listTools(): Promise<readonly McpTool[]> {
    const listed: McpTool[] = [];
    for (const config of this.#servers.values()) {
      for (const tool of this.#tools.get(config.name) ?? []) {
        // Deny-by-default: an un-allowlisted tool is never even advertised.
        if (!toolAllowlisted(config.toolsToExecute, tool.name)) continue;
        const entry: McpTool = {
          name: `${config.name}-${tool.name}`,
          serverName: config.name,
          remoteName: tool.name,
          inputSchema: tool.input_schema,
          autoExecute: toolAllowlisted(config.toolsToAutoExecute, tool.name),
        };
        if (tool.description !== undefined) entry.description = tool.description;
        listed.push(entry);
      }
    }
    return listed;
  }

  async toolByName(name: string): Promise<McpTool | undefined> {
    return (await this.listTools()).find((tool) => tool.name === name);
  }

  async callTool(
    tool: McpTool,
    args: JsonValue,
    identity: McpDispatchHeaders,
    context: DispatchContext,
  ): Promise<{ content: JsonValue; isError: boolean }> {
    const config = this.#servers.get(tool.serverName);
    if (config === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${tool.serverName} is not connected`,
      );
    }
    if (config.transport === "stdio") {
      // PORT-TODO(inventory-edge-control §MCP): stdio transport requires Containers.
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${config.name} uses the stdio transport, which Workers cannot host (no process spawn); move it to a Container or an HTTP transport`,
      );
    }
    if (!toolAllowlisted(config.toolsToExecute, tool.remoteName)) {
      throw new McpExecutionError(
        "tool_denied",
        `MCP tool ${config.name}-${tool.remoteName} is not allowlisted for execution`,
      );
    }
    const handler = this.#handlers.get(tool.serverName);
    if (handler === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${tool.serverName} has no connected session`,
      );
    }
    return handler(tool, args, identity, context);
  }
}

/** Deny-by-default allowlist check. Port of `manager::tool_allowlisted`. */
export function toolAllowlisted(allowlist: readonly string[], name: string): boolean {
  return allowlist.includes(name);
}

/**
 * Longest-prefix resolution of a namespaced `{server}-{remote}` tool name.
 * Port of `manager::resolve_namespaced_session`: a server named `a-b` wins over
 * a server named `a` for the tool `a-b-c`.
 */
export function resolveNamespacedTool(
  serverNames: readonly string[],
  name: string,
): { serverName: string; remoteName: string } | undefined {
  let best: { serverName: string; remoteName: string } | undefined;
  for (const serverName of serverNames) {
    if (!name.startsWith(`${serverName}-`)) continue;
    const remoteName = name.slice(serverName.length + 1);
    if (remoteName.trim().length === 0) continue;
    if (best === undefined || serverName.length > best.serverName.length) {
      best = { serverName, remoteName };
    }
  }
  return best;
}

export class InMemoryCredentialStore implements McpCredentialStorePort {
  readonly #flows = new Map<string, StoredMcpOauthFlow>();
  readonly #credentials = new Map<string, StoredMcpOauthCredential>();
  readonly #generations = new Map<string, number>();

  clear(): void {
    this.#flows.clear();
    this.#credentials.clear();
    this.#generations.clear();
  }

  /** Bump the actor's authorization generation (simulates an access change). */
  bumpGeneration(actor: McpIdentityActor, serverName: string): void {
    const key = actorKey(actor, serverName);
    this.#generations.set(key, (this.#generations.get(key) ?? 0) + 1);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async authorizationGeneration(actor: McpIdentityActor, serverName: string): Promise<number> {
    return this.#generations.get(actorKey(actor, serverName)) ?? 0;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async beginOauthFlow(flow: StoredMcpOauthFlow): Promise<void> {
    this.#flows.set(flow.id, flow);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async consumeOauthFlow(
    stateId: string,
    nowUnix: number,
  ): Promise<StoredMcpOauthFlow | undefined> {
    const flow = this.#flows.get(stateId);
    if (flow === undefined) return undefined;
    // Single-use AND time-bounded: a replayed or expired state is unknown.
    if (flow.consumedAtUnix !== undefined || flow.expiresAtUnix <= nowUnix) return undefined;
    this.#flows.set(stateId, { ...flow, consumedAtUnix: nowUnix });
    return flow;
  }

  async commitOauthCallback(
    flow: StoredMcpOauthFlow,
    credential: StoredMcpOauthCredential,
  ): Promise<boolean> {
    const generation = await this.authorizationGeneration(flow.actor, flow.serverName);
    if (generation !== flow.authorizationGeneration) return false;
    this.#credentials.set(actorKey(credential.actor, credential.serverName), credential);
    return true;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getCredential(
    actor: McpIdentityActor,
    serverName: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    return this.#credentials.get(actorKey(actor, serverName));
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async putCredential(credential: StoredMcpOauthCredential): Promise<void> {
    this.#credentials.set(actorKey(credential.actor, credential.serverName), credential);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async revokeCredential(
    actor: McpIdentityActor,
    serverName: string,
    nowUnix: number,
    outcome: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    const key = actorKey(actor, serverName);
    const credential = this.#credentials.get(key);
    if (credential === undefined || credential.revokedAtUnix !== undefined) return undefined;
    const revoked: StoredMcpOauthCredential = {
      ...credential,
      revokedAtUnix: nowUnix,
      updatedAtUnix: nowUnix,
      lastRevocationOutcome: outcome,
    };
    this.#credentials.set(key, revoked);
    return revoked;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async updateRevocationOutcome(
    actor: McpIdentityActor,
    serverName: string,
    outcome: string,
  ): Promise<void> {
    const key = actorKey(actor, serverName);
    const credential = this.#credentials.get(key);
    if (credential === undefined) return;
    this.#credentials.set(key, { ...credential, lastRevocationOutcome: outcome });
  }
}

function actorKey(actor: McpIdentityActor, serverName: string): string {
  return `${actor.tenantId} ${actor.workspaceId} ${actor.userId} ${serverName}`;
}

/** Derives the stable credential id. Port of `state_mcp_identity::credential_id`. */
export function credentialId(actor: McpIdentityActor, serverName: string): string {
  return `mcpid_${actor.tenantId}:${actor.workspaceId}:${actor.userId}:${serverName}`;
}

/**
 * The bundle the app resolves per request. `env` is the Worker environment; a
 * real deployment binds D1/KV/Secrets-Store-backed implementations here.
 */
export interface McpEnv {
  /**
   * DEV/TEST ONLY. When `"1"`, the app installs the in-memory ports above
   * (including a static API-key table). Any other value fails closed:
   * authentication returns 503 until real ports are bound.
   */
  FG_DEV_IN_MEMORY_PORTS?: string;

  /**
   * KV namespace holding in-flight per-user MCP OAuth flows
   * ({@link StoredMcpOauthFlow}). Dereferenced by {@link resolvePorts} through
   * `KvOauthFlowStore`; OPTIONAL here because the dev bundle runs without it
   * and its absence must produce a clean `not_ready`, not a `TypeError`.
   */
  MCP_OAUTH_KV?: KVNamespace;

  /**
   * Durable Object namespace providing the ATOMIC single-use claim on an
   * in-flight OAuth flow (`src/oauth-flow.ts`). One instance per state digest,
   * so two callbacks racing on the same `state` are serialized and exactly one
   * is served — the property Workers KV cannot express.
   *
   * OPTIONAL, and its absence is a real degradation rather than a failure:
   * {@link resolvePorts} falls back to `KvOauthFlowStore`, whose `get`+`delete`
   * is not indivisible. Bind it in production.
   */
  MCP_OAUTH_FLOWS?: DurableObjectNamespace<McpOauthFlowClaim>;

  /**
   * D1 database holding the sealed per-user identity grants
   * (`mcp_oauth_credentials`) and the tenant's upstream MCP server catalog
   * (`mcp_servers`). Dereferenced by {@link resolvePorts} through
   * `D1CredentialGrants` / `loadServerCatalog`; OPTIONAL for the same reason
   * as {@link MCP_OAUTH_KV}.
   */
  DB?: D1Database;

  /**
   * 32-byte AEAD key (base64 or hex) the stored grants are sealed under —
   * the Rust `FERROGATE_MCP_IDENTITY_KEY`.
   *
   * // PORT-TODO(inventory-edge-control §MCP): PLATFORM LIMIT — CF bindings,
   * // Secrets Store included, resolve at DEPLOY time. There is no runtime
   * // "open secret X by name/uuid" API, so this Worker cannot fetch its own
   * // key, cannot hold two key versions at once, and cannot rotate without a
   * // redeploy. Rust read the key from the process environment and could
   * // re-read it; a Worker cannot.
   * //
   * // IMPLEMENTED INSTEAD: the value is decoded (base64 or hex) and
   * // length-checked by `decodeIdentityKey`, which REFUSES anything that is
   * // not exactly 32 bytes, and a missing or malformed key makes
   * // {@link portsBound} false so `/readyz` answers 503 — instead of the
   * // Worker silently sealing grants under an ephemeral per-isolate key that
   * // would be lost on the next recycle.
   * //
   * // CONSEQUENCE: {@link StoredMcpOauthCredential.keyVersion} is carried on
   * // every stored grant but is never used to SELECT a key here. It is an
   * // honest field with no runtime resolver to feed it; key rotation is a
   * // redeploy plus a re-seal, not an online operation.
   */
  FERROGATE_MCP_IDENTITY_KEY?: string;
}

let devPorts: InMemoryMcpPorts | undefined;

/**
 * The in-memory port bundle, created once per isolate. Tests import this to
 * seed upstreams / API keys and to read the audit rows the request produced.
 */
export interface InMemoryMcpPorts extends McpPorts {
  auth: InMemoryAuth;
  entitlements: InMemoryEntitlements;
  upstreams: InMemoryUpstreams;
  assets: InMemoryAssets;
  credentials: InMemoryCredentialStore;
  audit: InMemoryAuditSink;
  metrics: InMemoryMetrics;
}

export function inMemoryPorts(): InMemoryMcpPorts {
  devPorts ??= {
    auth: new InMemoryAuth(),
    entitlements: new InMemoryEntitlements(),
    upstreams: new InMemoryUpstreams(),
    guardrails: new AllowAllGuardrails(),
    approvals: new AutoApproval(),
    assets: new InMemoryAssets(),
    credentials: new InMemoryCredentialStore(),
    oauth: unboundOauthProvider(),
    secrets: { resolve: async () => undefined },
    cipher: webCryptoIdentityCipher(),
    audit: new InMemoryAuditSink(),
    metrics: new InMemoryMetrics(),
    now: () => Math.floor(Date.now() / 1000),
  };
  return devPorts as InMemoryMcpPorts;
}

/** Reset every in-memory port. Tests call this in `beforeEach`. */
export function resetInMemoryPorts(): void {
  const ports = inMemoryPorts();
  ports.auth.clear();
  ports.entitlements.deniedTenants.clear();
  ports.upstreams.clear();
  ports.assets.clear();
  ports.credentials.clear();
  ports.audit.clear();
  ports.metrics.clear();
  ports.oauth = unboundOauthProvider();
  ports.secrets = { resolve: async () => undefined };
}

/** Replace the OAuth provider seam (tests bind a deterministic fake here). */
export function setOauthProvider(provider: OauthProviderPort): void {
  inMemoryPorts().oauth = provider;
}

/** Replace the secret resolver seam. */
export function setSecretResolver(resolver: SecretResolverPort): void {
  inMemoryPorts().secrets = resolver;
}

function unboundOauthProvider(): OauthProviderPort {
  const unavailable = (): never => {
    throw new McpExecutionError(
      "mcp_server_unavailable",
      "no OAuth provider is bound to this Worker",
    );
  };
  return {
    discover: async () => unavailable(),
    exchangeAuthorizationCode: async () => unavailable(),
    refresh: async () => unavailable(),
    validateIdToken: async () => unavailable(),
    revoke: async () => unavailable(),
  };
}

/**
 * AES-GCM envelope encryption over a per-isolate key.
 *
 * PORT-TODO(inventory-edge-control §MCP): the Rust implementation seals stored
 * grants with XChaCha20-Poly1305 under `FERROGATE_MCP_IDENTITY_KEY`. WebCrypto
 * in workerd has no XChaCha20; AES-256-GCM is the closest correct primitive
 * (AEAD, 96-bit random nonce, same AAD binding). The key MUST come from Secrets
 * Store at deploy time — the ephemeral fallback below only exists so the
 * in-memory dev bundle is usable, and it deliberately loses all stored grants
 * when the isolate recycles rather than persisting a weak key.
 */
export function webCryptoIdentityCipher(rawKey?: Uint8Array): IdentityCipherPort {
  let keyPromise: Promise<CryptoKey> | undefined;
  let signingPromise: Promise<CryptoKey> | undefined;
  const material =
    rawKey ??
    (() => {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      return bytes;
    })();

  const aeadKey = (): Promise<CryptoKey> => {
    keyPromise ??= crypto.subtle.importKey("raw", material as BufferSource, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
    return keyPromise;
  };

  return {
    async encrypt(plaintext, aad) {
      const nonce = new Uint8Array(12);
      crypto.getRandomValues(nonce);
      const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad as BufferSource },
        await aeadKey(),
        plaintext as BufferSource,
      );
      return { nonce, ciphertext: new Uint8Array(sealed) };
    },
    async decrypt(nonce, ciphertext, aad) {
      if (nonce.length !== 12) throw new Error("MCP identity ciphertext nonce is invalid");
      const opened = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
        await aeadKey(),
        ciphertext as BufferSource,
      );
      return new Uint8Array(opened);
    },
    signingKey() {
      // Domain-separated from the AEAD key exactly as the Rust
      // `IdentityCipher::signing_key` is.
      signingPromise ??= (async () => {
        const digest = await crypto.subtle.digest(
          "SHA-256",
          concatBytes(new TextEncoder().encode("ferrogate:mcp:signed-identity:v1"), material),
        );
        return crypto.subtle.importKey("raw", digest, { name: "HMAC", hash: "SHA-256" }, false, [
          "sign",
        ]);
      })();
      return signingPromise;
    },
  };
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

/**
 * Whether the deploy-time bindings the DURABLE identity store needs are all
 * present: the D1 database, the KV namespace, and usable AEAD key material.
 *
 * All three or none — a Worker holding D1 but no key would seal grants under an
 * ephemeral per-isolate key and lose every one of them on the next recycle,
 * which is worse than refusing traffic.
 */
export function durableIdentityBound(env: McpEnv): boolean {
  return (
    env.DB !== undefined &&
    env.MCP_OAUTH_KV !== undefined &&
    decodeIdentityKey(env.FERROGATE_MCP_IDENTITY_KEY) !== undefined
  );
}

/**
 * Whether this Worker has a usable port bundle for authenticated traffic.
 *
 * This is the single source of truth {@link resolvePorts} branches on, so
 * `/readyz` cannot claim readiness on an isolate whose auth port is
 * {@link UnboundAuth} — the Workers equivalent of the Rust readiness probe
 * reporting `not_ready` while the cluster has no healthy peer.
 *
 * It is now a REAL binding check on the durable path
 * ({@link durableIdentityBound}) rather than the dev flag alone.
 *
 * // PORT-TODO(inventory-edge-control §MCP): NOT a platform limit — a
 * // cross-app wiring deferral. The last port with no durable
 * // implementation is {@link AuthPort} — the tenant API-key table lives in the
 * // control plane (`apps/control-plane`), not here, so binding it means either
 * // a `[[services]]` service binding to that Worker or a shared D1 read of its
 * // `api_keys` table. Until one exists, a non-dev Worker reports NOT READY
 * // even when {@link durableIdentityBound} is satisfied, because authenticating
 * // a caller is a precondition for every authenticated surface. The identity,
 * // flow and catalog halves ARE durable-bound below.
 */
export function portsBound(env: McpEnv): boolean {
  return env.FG_DEV_IN_MEMORY_PORTS === "1";
}

/**
 * Resolve the port bundle for a request.
 *
 * Three postures, in order:
 *
 *  1. **dev bundle** (`FG_DEV_IN_MEMORY_PORTS === "1"`) — everything in memory.
 *  2. **durable identity** — D1 + KV + key material bound: the credential store
 *     and cipher are the real, isolate-surviving implementations, so a revoked
 *     grant stays revoked and an OAuth callback that lands on a different
 *     isolate than the one that began the flow still completes. `auth` is still
 *     {@link UnboundAuth}, so the surface answers 503 rather than defaulting
 *     open — see {@link portsBound}.
 *  3. **nothing bound** — fail closed.
 *
 * Within posture 2 the flow store is chosen by capability, not by config: when
 * {@link McpEnv.MCP_OAUTH_FLOWS} is bound the single-use claim is the ATOMIC
 * Durable-Object one, and only a deployment missing that binding degrades to
 * KV's non-indivisible `get`+`delete`.
 */
export function resolvePorts(env: McpEnv): McpPorts {
  if (env.FG_DEV_IN_MEMORY_PORTS === "1") return inMemoryPorts();
  const ports = inMemoryPorts();
  if (durableIdentityBound(env)) {
    return {
      ...ports,
      auth: new UnboundAuth(),
      credentials: new DurableCredentialStore(
        env.MCP_OAUTH_KV as KVNamespace,
        env.DB as D1Database,
        env.MCP_OAUTH_FLOWS === undefined
          ? undefined
          : new DurableOauthFlowStore(env.MCP_OAUTH_FLOWS),
      ),
      cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY) as IdentityCipherPort,
    };
  }
  return { ...ports, auth: new UnboundAuth() };
}
