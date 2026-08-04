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
 * ## Which ports are actually BOUND to a real package (keep this honest)
 *
 * A narrow port whose only implementation is the in-memory default is a
 * DEFERRAL wearing an abstraction's clothes: the package exists, the tests are
 * green, and the deployed Worker never calls it. Current state:
 *
 * | port          | production binding                                        |
 * |---------------|-----------------------------------------------------------|
 * | `guardrails`  | `@ferrogate/guardrails` `DeterministicDetector` — BOUND    |
 * | `secrets`     | `@ferrogate/secrets` `SecretResolverRegistry` — BOUND      |
 * | `credentials` | `DurableCredentialStore` (D1 + KV + DO) — BOUND           |
 * | `cipher`      | `identityCipherFrom(FERROGATE_MCP_IDENTITY_KEY)` — BOUND   |
 * | `upstreams`   | `HttpMcpUpstreams` + the `MCP_SESSION` DO — BOUND          |
 * | `auth`        | `D1McpAuth` over the CONTROL database (`src/auth.ts`) — BOUND |
 * | `admission`   | `McpAdmissionGate` (`src/admission/`) — BOUND              |
 * | `approvals`   | `D1ToolApprovals` over the CONTROL database — BOUND        |
 * | `oauth`       | {@link unboundOauthProvider} — NOT BOUND, fails closed     |
 * | `assets`      | {@link D1R2AssetReader} (D1 + R2) — BOUND (see below)      |
 * | `audit`       | {@link InMemoryAuditSink} — isolate-local (see wrangler)   |
 *
 * `guardrails`, `secrets`, `auth` and `approvals` are each bound in EVERY
 * posture that can serve them, and each has a mount-gate test that goes red
 * when the binding is dropped (`test/guardrails.test.ts`,
 * `test/secrets-mount.test.ts`, `test/d1-auth.test.ts`,
 * `test/approvals.test.ts`).
 *
 * This table is load-bearing documentation and it goes stale silently: it said
 * `approvals` was {@link AutoApproval} with "NO durable queue exists" for a
 * whole wave AFTER `src/approvals.ts` landed and {@link resolvePorts} bound it,
 * which reads as "every non-auto-execute MCP tool still runs unapproved" — the
 * exact opposite of the truth, and the kind of note that makes the next reader
 * re-implement something that is already there. When you change a binding in
 * {@link resolvePorts}, change this row in the same edit.
 *
 * PORT-TODO(L: inventory-edge-control §MCP): PLATFORM LIMIT — stdio MCP upstreams
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
import {
  DeterministicDetector,
  type SecretPattern,
  envelopeManagedAction,
  flattenedText,
} from "@ferrogate/guardrails";
import { type EnvLike, SecretResolverRegistry } from "@ferrogate/secrets";
import { EnvBindingTenantDatabaseRouter } from "@ferrogate/storage";

// `./durable.js` imports the TYPES and `webCryptoIdentityCipher` back out of
// this module. The cycle is safe because neither side touches the other at
// module-evaluation time — every reference is inside a function body.
// `./auth.js` imports the AuthPort TYPES back out of this module. The cycle is
// safe for the same reason `./durable.js`'s is: every reference on both sides is
// inside a function body, so nothing is evaluated at module-load time.
// `./admission/` is a LEAF as far as this module is concerned: it declares the
// identity it reads structurally (`AdmissionIdentity`) rather than importing
// `AuthContext` back out of here, so there is no cycle in either direction.
import {
  ADMIT_ALL,
  type AdmissionPort,
  type RateLimiterNamespace,
  admissionFromEnv,
} from "./admission/index.js";
import { D1ToolApprovals } from "./approvals.js";
import { D1McpAuth, type D1McpAuthOptions } from "./auth.js";
import { DurableCredentialStore, decodeIdentityKey, identityCipherFrom } from "./durable.js";
import { D1ToolEntitlements } from "./entitlements.js";
import { durableManagedActionGuardrails } from "./guardrails.js";
import type { ParsedToolDef } from "./jsonrpc.js";
import {
  D1McpTenancyLifecycleGate,
  type TenancyLifecycleGatePort,
  UnboundLifecycleGate,
} from "./lifecycle.js";
// `./multiplex.js` is a LEAF: it imports only the `McpTool` TYPE back out of
// this module, which is erased, so there is no value-level cycle to reason
// about even though the dependency reads both ways on paper.
import {
  type McpFanIn,
  type McpToolResolution,
  namespacedToolName,
  resolveAcrossCatalog,
} from "./multiplex.js";
import { DurableOauthFlowStore, type McpOauthFlowClaim } from "./oauth-flow.js";
// `./rbac.js` imports the `AuthContext` TYPE back out of this module. The cycle
// is safe for the same reason `./auth.js`'s is: the import is type-only, so
// nothing is evaluated in either direction at module load.
import { type RbacAuthorizerPort, UnboundRbacAuthorizer, rbacAuthorizerFromEnv } from "./rbac.js";
// TYPE-ONLY. `./session.js` imports `McpTool` back out of this module, also
// type-only, so nothing is evaluated in either direction at module load.
import type { FerroGateMcpSession } from "./session.js";
// TYPE-ONLY, for the same reason: `./unified.ts` imports nothing from here at
// runtime, so the namespace field below costs no module-load coupling.
import type { FerroGateMcpUnifiedSession } from "./unified.js";

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
  /**
   * The subtractive half of the multiplex filter pair (#687).
   *
   * ABSENT means "exclude nothing", which is the only backwards-compatible
   * default and the only one a database that predates the column can express.
   * It is NOT the fail-open direction it looks like: the INCLUDE list is still
   * deny-by-default, so an absent exclude list leaves a server exposing exactly
   * what it exposed before this field existed.
   *
   * EXCLUDE WINS over {@link toolsToExecute}. See {@link toolPermitted} for why
   * that is forced rather than chosen.
   */
  toolsToExclude?: string[];
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
  /**
   * TOK-12 `api_keys.request_limit_per_minute` — Rust
   * `AuthContext.request_limit_per_minute`, the per-CREDENTIAL RPM cap that is
   * independent of the `quota_policies` chain.
   *
   * `undefined` means the row set no cap. `0` is a REAL value ("refuse every
   * request"), so no consumer may treat this field as falsy-means-absent.
   */
  requestLimitPerMinute?: number;
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
  /**
   * #687: where the code that RESOLVED an upstream reports which one it was.
   *
   * Optional, so every existing construction site keeps compiling and every
   * path that has no session simply writes nowhere. The alternative — the
   * ingress guessing the serving upstream from the flat tool name — is exactly
   * the defect `#677/#678`'s attribution and this PR's `resolveTool` closed.
   */
  upstreams?: UpstreamAttributionSink;
}

/**
 * The upstreams that contributed to one response (#687).
 *
 * `note` is the upstream that SERVED something; `noteFailure` is one whose own
 * session could not be reached on this request. The second is how a client
 * session learns that one leg of its fan-out dropped mid-conversation while the
 * session itself stays open.
 */
export interface UpstreamAttributionSink {
  note(server: string): void;
  noteFailure(server: string, message: string): void;
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
  /**
   * The multiplexed fan-in: the union of every reachable upstream's
   * allowlisted tools, AND the upstreams that could not be reached (#687).
   *
   * Both halves are returned together on purpose. A signature that returned
   * only the tools is what allowed a partial upstream failure to reach the
   * client as a silently shorter list, which an agent reads as "that tool does
   * not exist" — strictly worse than an error.
   */
  fanIn(): Promise<McpFanIn>;
  /**
   * Namespaced, allowlisted tools visible to this caller.
   *
   * The lossy half of {@link fanIn}, kept because most callers genuinely only
   * want the union. Anything that reports to a client must use `fanIn`.
   */
  listTools(): Promise<readonly McpTool[]>;
  /**
   * Resolve one namespaced tool name against the multiplexed catalogue (#687).
   *
   * Returns a RESOLUTION rather than a tool because "no such tool" and "two
   * upstreams claim this name" are different answers and only the second one is
   * fixable by the caller. `selector` is the caller's explicit
   * `ferrogate/server`; see `./multiplex.ts` for the whole contract.
   */
  resolveTool(name: string, selector?: string | undefined): Promise<McpToolResolution>;
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

/**
 * The guardrail seam of the tool chokepoint.
 *
 * Both legs take the RESOLVED {@link McpTool}, not its namespaced name: Rust's
 * managed-action binding is derived from the action itself, whose
 * `server_name` / `tool_name` are separate fields, and the canonical target
 * `mcp:{server}:{tool}` needs both. Re-splitting `"{server}-{remote}"` here
 * would have to guess where the boundary is — `-` is legal inside a remote tool
 * name — and a wrong guess mis-addresses the policy selector, which is a
 * guardrail applied to the wrong upstream.
 */
export interface GuardrailsPort {
  /** Runs BEFORE execution: may block or quarantine the arguments. */
  inspectInput(context: DispatchContext, tool: McpTool, args: JsonValue): Promise<GuardrailVerdict>;
  /** Runs AFTER execution: may redact or withhold the result. */
  inspectOutput(
    context: DispatchContext,
    tool: McpTool,
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
 * Time budget handed to the detector, mirroring Rust's per-detector deadline.
 *
 * The deterministic detector is in-process and does not block on I/O, so this
 * is a ceiling rather than an expected cost; it exists so a pathological regex
 * over a large tool result cannot hold the request open indefinitely.
 */
export const MCP_GUARDRAIL_BUDGET_MS = 250;

/** The guardrail class every action raised by this Worker carries. */
export const MCP_MANAGED_ACTION_CLASS = "mcp";

/**
 * Rust `ManagedExternalAction::target()` for the `McpTool` arm:
 * `mcp:{server_name}:{tool_name}`. It is the addressing half of what the
 * detector scans, and the string a managed-action policy's `targets` selector
 * is matched against, so the spelling is load-bearing.
 */
export function managedActionTarget(serverName: string, remoteName: string): string {
  return `mcp:${serverName}:${remoteName}`;
}

/**
 * Rust `managed_action_guardrail::payload_text`: a bare JSON string is scanned
 * as-is (no enclosing quotes, which would split a keyword away from its
 * neighbours), anything else by its compact JSON encoding.
 */
export function guardrailPayloadText(value: JsonValue): string {
  return typeof value === "string" ? value : JSON.stringify(value ?? null);
}

/**
 * Configuration for {@link deterministicManagedActionGuardrails}, mirroring the
 * `{ keywords?, regex?, secretPatterns? }` shape `apps/agent-runtime` reads for
 * the A2A stages plus the managed-action selector Rust uses to pick policies.
 */
export interface ManagedActionGuardrailConfig {
  readonly keywords?: readonly string[];
  readonly regex?: readonly string[];
  readonly secretPatterns?: readonly SecretPattern[];
  /**
   * Rust `ManagedActionSelector.targets`. EMPTY means every target, exactly as
   * an empty selector matches everything in `ferrogate-guardrails::policy`.
   * A non-empty list restricts the detector to those canonical targets, so a
   * policy written for one upstream does not silently police another.
   */
  readonly targets?: readonly string[];
}

/**
 * The MCP tool chokepoint's guardrail seam, bound to the REAL clean-room
 * deterministic detector.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/managed_action_guardrail.rs`
 * (`evaluate_managed_action_guardrail_async` + `payload_text`) for the
 * `ManagedActionClass::Mcp` arm:
 *
 *  - the envelope is the MANAGED-ACTION one, not the chat one:
 *    `GuardrailEnvelope::managed_action(stage, "managed_action:{target}", text)`,
 *    whose content source is `tool_arguments` on the request stage and
 *    `tool_result` on the response stage. Registering the detector for only one
 *    of those sources would silently pass a whole direction, so both are
 *    declared in `supported_sources`;
 *  - the request-stage text is Rust `managed_action_input_text`: the canonical
 *    target, then a newline, then the arguments — so a policy can match on the
 *    addressing (`mcp:github:create_issue`) or on the payload;
 *  - the response-stage text is the rendered tool result;
 *  - the deadline is ABSOLUTE (`Date.now() + budget`), because
 *    `DeterministicDetector.evaluate` compares its argument against
 *    `Date.now()`. Passing the budget itself makes every evaluation throw —
 *    which, read as a pass, silently opens the chokepoint;
 *  - a detector error FAILS CLOSED. A detector that could not run has not
 *    cleared the content.
 *
 * A verdict maps to the {@link GuardrailVerdict} vocabulary the chokepoint in
 * `src/tools.ts` already enforces: `block` before execution, `withhold` after.
 * Rust refuses at both stages, and so does this — `withhold` is the response
 * stage's refusal, not a softer outcome.
 *
 * An UNCONFIGURED guardrail (no keywords, no regex, no secret patterns) matches
 * nothing and allows everything: that is the answer Rust's `match_guardrail`
 * gives when no managed-action policy is registered, and wiring this port must
 * not change the behavior of a deployment that configured no detectors.
 */
export function deterministicManagedActionGuardrails(
  config: ManagedActionGuardrailConfig,
): GuardrailsPort {
  const keywords = [...(config.keywords ?? [])];
  const regex = [...(config.regex ?? [])];
  const secretPatterns = [...(config.secretPatterns ?? [])];
  const targets = [...(config.targets ?? [])];
  const configured = keywords.length > 0 || regex.length > 0 || secretPatterns.length > 0;

  const detector = configured
    ? DeterministicDetector.new({
        id: "mcp.managed_action.deterministic",
        // Both managed-action sources, for the reason in the module note above.
        supported_sources: ["tool_arguments", "tool_result"],
        keywords,
        regex,
        secret_patterns: secretPatterns,
      })
    : undefined;

  /** Rust `managed_selector_matches`: an EMPTY target list matches everything. */
  const selects = (target: string): boolean => targets.length === 0 || targets.includes(target);

  const evaluate = async (
    stage: "request" | "response",
    context: DispatchContext,
    toolName: string,
    renderText: () => string,
    target: string,
  ): Promise<GuardrailVerdict> => {
    if (detector === undefined || !selects(target)) return { action: "allow" };
    const refusal = stage === "request" ? "block" : "withhold";
    let result: Awaited<ReturnType<typeof detector.evaluate>>;
    try {
      // Rendering the payload is INSIDE the guard on purpose, and it is a thunk
      // for exactly that reason: `JSON.stringify` runs caller-controlled
      // `toJSON`/getters, so it can throw. A failure THERE has cleared exactly
      // as little as a failure inside the detector, and must refuse rather than
      // escape as a 500 that some outer handler could mistake for a clean pass.
      const envelope = envelopeManagedAction(stage, `managed_action:${target}`, renderText());
      result = await detector.evaluate(
        {
          protocol: "managed_action",
          stage,
          // `DetectorTenant` has no tenant field of its own — Rust attributes a
          // guardrail evaluation by ORGANIZATION.
          tenant: { organization_id: context.auth.organizationId },
          provider: target,
          text: flattenedText(envelope),
          segments: envelope.segments,
        },
        // ABSOLUTE deadline, not a duration.
        Date.now() + MCP_GUARDRAIL_BUDGET_MS,
      );
    } catch (error) {
      return {
        action: refusal,
        reason:
          `mcp ${stage}-stage guardrail could not be evaluated for ${toolName}: ` +
          `${error instanceof Error ? error.message : "detector error"}`,
      };
    }
    if (result.verdict === "pass") return { action: "allow" };
    // Evidence only — the matched TEXT is never echoed, which is the crate's
    // standing invariant: a refusal that quoted the secret it caught would
    // defeat the detector it came from.
    const severities = result.findings.map((finding) => finding.severity).join(", ");
    return {
      action: refusal,
      reason:
        `mcp ${stage}-stage guardrail matched ${result.findings.length} finding(s) ` +
        `[${severities}] on ${toolName}`,
    };
  };

  return {
    async inspectInput(context, tool, args) {
      const target = managedActionTarget(tool.serverName, tool.remoteName);
      // Rust `managed_action_input_text`: target, newline, then the payload.
      return evaluate(
        "request",
        context,
        tool.name,
        () => `${target}\n${guardrailPayloadText(args)}`,
        target,
      );
    },
    async inspectOutput(context, tool, content) {
      const target = managedActionTarget(tool.serverName, tool.remoteName);
      return evaluate("response", context, tool.name, () => guardrailPayloadText(content), target);
    },
  };
}

/**
 * Approves anything already allowlisted.
 *
 * MARKER CLOSED (was: "NOT a platform limit — a deferral on ANOTHER APP … the
 * human-approval queue is control-plane state, so binding it means a
 * `[[services]]` service binding or a shared D1 read, neither of which this
 * Worker can create unilaterally"). It was the shared D1 read, and it needed no
 * new binding: `apps/control-plane` keeps approvals as `control_plane_resources`
 * rows of kind `tool-approvals` in the CONTROL database this Worker already
 * binds as `env.DB`. {@link D1ToolApprovals} (`src/approvals.ts`) reads and
 * raises them, and {@link resolvePorts} binds it wherever `env.DB` exists.
 *
 * THIS class survives ONLY as the no-database fallback, and its behaviour is
 * the reason the closure mattered: it approves EVERYTHING, so a deployment
 * running on it executes every non-`auto_execute` MCP tool with no human
 * decision at all. The deny-by-default `toolsToExecute` allowlist in
 * `src/tools.ts` is enforced independently and still refuses an un-allowlisted
 * tool; what this class skips is the interactive step-up on an allowlisted one.
 */
export class AutoApproval implements ApprovalPort {
  // eslint-disable-next-line @typescript-eslint/require-await
  async require(): Promise<undefined> {
    return undefined;
  }
}

/**
 * In-memory asset catalog — FALLBACK, no longer the production path.
 *
 * PORT-TODO(P: inventory-edge-control §MCP) — KEPT as the graceful fallback
 * when `env.ASSETS` or `env.TENANT_DB` is absent (offline / tests). The
 * production path is now {@link D1R2AssetReader} (D1 + R2), selected by
 * {@link resolvePorts} when both bindings are present.
 *
 * The `[[r2_buckets]]` stanza binding `ASSETS` and the `[[d1_databases]]`
 * stanza binding `TENANT_DB` are declared in `apps/mcp/wrangler.toml`. Both
 * are flat bindings — tenant isolation is provided by the
 * `WHERE tenant_id = ?1` predicate on every query, not by per-tenant database
 * routing.
 *
 * NOTE (memory: the live account has R2 unactivated) that a bucket must be
 * enabled on the account first; the `[[r2_buckets]]` stanza against an
 * account without the R2 plan fails the deploy with error 10042, not 10000.
 *
 * CONSEQUENCE while this fallback is active: assets do not survive an
 * isolate recycle, so `resources/list` and `resources/read` answer only for
 * what this isolate was seeded with. The #366 property that DOES hold
 * regardless of the backing store is pinned in `read` below and by
 * `test/assets.test.ts`: an undownloadable (pending / quarantined) asset is
 * indistinguishable from a missing one.
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
    const prefix = `${tenantId}\u0000`;
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
  return `${tenantId}\u0000${assetType}\u0000${name}\u0000${version}`;
}

// ---------------------------------------------------------------------------
// D1 + R2 asset reader — the production AssetReaderPort
// ---------------------------------------------------------------------------

/**
 * The D1+R2-backed {@link AssetReaderPort}.
 *
 * Queries `stored_assets` from the TENANT database (`env.TENANT_DB`) for
 * asset metadata, then fetches the object body from `env.ASSETS` (R2) using
 * the `storage_uri` column as the object key.
 *
 * Selected by {@link resolvePorts} when BOTH `env.ASSETS` and `env.TENANT_DB`
 * are present and `FG_DEV_IN_MEMORY_PORTS !== "1"`. Uses
 * {@link InMemoryAssets} when either binding is absent or when the dev posture
 * explicitly selects in-memory ports.
 *
 * ## #366 withholding
 *
 * On the READ side, this class enforces the withholding directly: an asset
 * whose `visibility` is not `'visible'` or whose `yanked` flag is `true`
 * returns `{ kind: "not_found" }` — indistinguishable from a missing one.
 *
 * On the LISTING side, this class returns every row (including hidden ones)
 * with `downloadable` computed per row: `true` only for visible, non-yanked
 * rows, and `false` otherwise. The actual withholding — the filter that
 * removes hidden assets from the MCP resource listing — happens one layer up
 * in {@link dispatch.ts}:
 *
 * ```ts
 * const downloadable = assets.filter((asset) => asset.downloadable);
 * ```
 *
 * Both halves are pinned by `test/d1-r2-asset-reader.test.ts`.
 *
 * ## Integrity verification
 *
 * The `content_hash` column (sha256 hex) is verified against the fetched R2
 * object body. A mismatch returns `{ kind: "integrity" }` — the same error
 * the REST asset pull returns.
 */
export class D1R2AssetReader implements AssetReaderPort {
  readonly #db: D1Database;
  readonly #bucket: R2Bucket;

  constructor(db: D1Database, bucket: R2Bucket) {
    this.#db = db;
    this.#bucket = bucket;
  }

  async list(tenantId: string): Promise<readonly StoredAsset[]> {
    const rows = await this.#db
      .prepare(
        `SELECT asset_type, name, version, content_type, content_hash, size_bytes, yanked, visibility FROM stored_assets WHERE tenant_id = ?1`,
      )
      .bind(tenantId)
      .all<Row>();
    return (rows.results ?? []).map((row) => rowToStoredAsset(row));
  }

  async read(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<
    { ok: true; asset: StoredAsset; content: Uint8Array } | { ok: false; error: AssetReadFailure }
  > {
    const rows = await this.#db
      .prepare(
        `SELECT asset_type, name, version, content_type, content_hash, size_bytes, storage_uri, yanked, visibility FROM stored_assets WHERE tenant_id = ?1 AND asset_type = ?2 AND name = ?3 AND version = ?4`,
      )
      .bind(tenantId, assetType, name, version)
      .all<Row>();
    const row = (rows.results ?? [])[0];
    if (row === undefined) return { ok: false, error: { kind: "not_found" } };

    // #366: an undownloadable (pending / quarantined / yanked) asset is
    // indistinguishable from a missing one at the read chokepoint.
    const downloadable = isDownloadable(row);
    if (!downloadable) return { ok: false, error: { kind: "not_found" } };

    const storageUri = text(row.storage_uri);
    if (storageUri === "") {
      return { ok: false, error: { kind: "storage", message: "asset has no storage URI" } };
    }

    let object: R2ObjectBody | null;
    try {
      object = await this.#bucket.get(storageUri);
    } catch (cause) {
      return {
        ok: false,
        error: {
          kind: "bucket_unavailable",
          message: `R2 get failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        },
      };
    }
    if (object === null) {
      return { ok: false, error: { kind: "not_found" } };
    }

    const content = new Uint8Array(await object.arrayBuffer());

    // Integrity check: sha256 of the fetched body must match the recorded hash.
    const recordedHash = text(row.content_hash);
    if (recordedHash !== "") {
      const digest = await crypto.subtle.digest("SHA-256", content);
      const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (hex !== recordedHash) {
        return { ok: false, error: { kind: "integrity" } };
      }
    }

    return {
      ok: true,
      asset: rowToStoredAsset(row),
      content,
    };
  }
}

/** A raw D1 result row. */
interface Row {
  [column: string]: unknown;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : String(value ?? "");
}

function integer(value: unknown): number {
  return typeof value === "number" ? value : Number(value ?? 0);
}

function boolFromSqlite(value: unknown): boolean {
  return value === 1 || value === true || value === "1";
}

/**
 * SQLite stores `visibility` as TEXT. `'visible'` is the only value that
 * makes an asset downloadable; anything else (including `NULL`, `'pending_scan'`
 * and `'quarantined'`) is withheld.
 */
function isDownloadable(row: Row): boolean {
  return text(row.visibility) === "visible" && !boolFromSqlite(row.yanked);
}

/** Map a D1 row to the MCP's {@link StoredAsset}. */
function rowToStoredAsset(row: Row): StoredAsset {
  return {
    assetType: text(row.asset_type),
    name: text(row.name),
    version: text(row.version),
    contentType: text(row.content_type),
    sizeBytes: integer(row.size_bytes),
    sha256: text(row.content_hash),
    downloadable: isDownloadable(row),
  };
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
  /**
   * The ADMISSION half of Rust's `authenticate()` (`auth.rs::finalize_auth`):
   * quota scope, monthly budget, prepaid wallet, per-minute request window.
   *
   * Separate from {@link AuthPort} because the two answer different questions —
   * "who is this" versus "may they spend" — and because a credential that is
   * perfectly valid can still be refused here. `src/http.ts` runs them in that
   * order, which is the order Rust runs them in.
   */
  admission: AdmissionPort;
  /**
   * The TENANCY LIFECYCLE gate — `src/lifecycle.ts`, `docs/rewrite/
   * FLEET-CONSISTENCY.md` finding FC-2.
   *
   * Distinct from {@link AuthPort} for the same reason `apps/gateway` keeps
   * them apart: that port answers "is this credential live", this one answers
   * "is the TENANCY behind it still allowed to transact". A perfectly healthy
   * key belonging to a suspended tenant resolves and is then refused here —
   * `403 tenancy_suspended`, never the 401 a dead key gets.
   *
   * It runs BETWEEN the credential and {@link admission}, which is Rust's order
   * in `finalize_auth` and is the control rather than a convenience: a
   * suspended tenant must never reach the step that authorizes spend.
   */
  lifecycle: TenancyLifecycleGatePort;
  /**
   * THE RBAC GATE — an operation's `rbac_action` (`docs/rewrite/
   * FLEET-CONSISTENCY.md` finding **FC-7**), see `src/rbac.ts`.
   *
   * Distinct from {@link entitlements}, which asks a different question and
   * gets a different answer: that port is the PLAN-or-ROLE tool-execution
   * ladder (`plans.mcp_enabled` OR the `mcp.execute` permission, either
   * granting), while this one is the operation's own declared action, where the
   * role graph is the only authority. Collapsing them would let a plan flag
   * grant an action an operator's role explicitly withholds.
   *
   * It runs AFTER {@link lifecycle} and BEFORE {@link admission}, which is
   * where `apps/gateway` and `apps/control-plane` run it: an authorization
   * refusal must not first charge the caller's RPM window, or a client looping
   * on a denied action would deny service to its own permitted ones.
   */
  rbac: RbacAuthorizerPort;
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
  async fanIn(): Promise<McpFanIn> {
    const listed: McpTool[] = [];
    for (const config of this.#servers.values()) {
      for (const tool of this.#tools.get(config.name) ?? []) {
        // Deny-by-default MINUS the exclude list (#687): an un-allowlisted or
        // explicitly excluded tool is never even advertised.
        if (!toolPermitted(config, tool.name)) continue;
        const entry: McpTool = {
          name: namespacedToolName(config.name, tool.name),
          serverName: config.name,
          remoteName: tool.name,
          inputSchema: tool.input_schema,
          autoExecute: toolAllowlisted(config.toolsToAutoExecute, tool.name),
        };
        if (tool.description !== undefined) entry.description = tool.description;
        listed.push(entry);
      }
    }
    // An in-memory server cannot be unreachable, so `degraded` is always empty
    // here — the honest answer, not a stub.
    return { tools: listed, degraded: [] };
  }

  async listTools(): Promise<readonly McpTool[]> {
    return (await this.fanIn()).tools;
  }

  /**
   * #687: resolved against the materialised catalogue, exactly as
   * `HttpMcpUpstreams` does — the two hosts used to disagree about collisions
   * (this one took the FIRST exact match, that one the LONGEST server prefix),
   * which meant the dev bundle and production routed the same name to different
   * upstreams.
   */
  async resolveTool(name: string, selector?: string | undefined): Promise<McpToolResolution> {
    return resolveAcrossCatalog(await this.listTools(), name, selector);
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
      // PORT-TODO(L: inventory-edge-control §MCP): PLATFORM LIMIT — stdio requires
      // a process to spawn; workerd has none. KEPT, pinned end-to-end on the
      // deployed app by `test/stdio-limit.test.ts` (removing this branch turns
      // that suite red), and explained in full in `src/transport.ts`.
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${config.name} uses the stdio transport, which Workers cannot host (no process spawn); move it to a Container or an HTTP transport`,
      );
    }
    if (!toolPermitted(config, tool.remoteName)) {
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

/** The subtractive half. An absent list excludes nothing. */
export function toolExcluded(denylist: readonly string[] | undefined, name: string): boolean {
  return denylist?.includes(name) ?? false;
}

/**
 * The multiplex filter pair (#687): INCLUDE ∖ EXCLUDE, by the upstream's own
 * remote tool name.
 *
 * ## Why EXCLUDE wins, and why that is forced rather than preferred
 *
 * `toolsToExecute` is deny-by-DEFAULT. A tool that is listable or callable at
 * all is therefore NECESSARILY on the include list. So if include won a
 * conflict, writing a name into the exclude list could never change any
 * outcome — the exclude list would be decorative, and an operator who added an
 * exclusion and watched the tool stay callable would be holding a security
 * hole, not a preference mismatch. There is exactly one order in which both
 * lists mean something, and this is it.
 *
 * It is also the fail-CLOSED direction, which is the tie-break this app applies
 * everywhere else a decode or a policy is ambiguous.
 *
 * ## Where it must be applied
 *
 * EVERY read, not only where a tool list is first discovered. `HttpMcpUpstreams`
 * caches the discovered list per isolate and publishes it to the shared
 * `MCP_SESSION` Durable Object, so an exclusion applied only at discovery would
 * leave every warm session serving the excluded tool until its next reconnect.
 * A deny rule that takes effect eventually is not a deny rule.
 */
export function toolPermitted(
  config: Pick<McpServerConfig, "toolsToExecute" | "toolsToExclude">,
  remoteName: string,
): boolean {
  if (toolExcluded(config.toolsToExclude, remoteName)) return false;
  return toolAllowlisted(config.toolsToExecute, remoteName);
}

// `resolveNamespacedTool` — the longest-prefix port of
// `manager::resolve_namespaced_session` — used to live here and is DELETED
// (#687), not moved. It answered "which single upstream owns this flat name"
// by looking only at the string, and with two upstreams whose namespaced names
// collide it silently picked one and made the other's tool permanently
// unreachable. `./multiplex.ts`'s `candidateServerNames` returns EVERY prefix
// match, and the answer then comes from those upstreams' catalogues. Leaving
// the old helper exported would only invite a second, divergent resolver.

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
  return `${actor.tenantId}\u0000${actor.workspaceId}\u0000${actor.userId}\u0000${serverName}`;
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
   * DEV/TEST ONLY. JSON `{ keywords?, regex?, secretPatterns?, targets? }`
   * configuring the managed-action (MCP tool argument / tool result) guardrail
   * evaluated by the real `@ferrogate/guardrails` deterministic detector.
   *
   * ABSENT OR EMPTY means NO detector is configured, which matches nothing and
   * allows everything — the same answer Rust's `match_guardrail` gives when no
   * managed-action policy is registered. This is deliberately NOT the
   * enforcement policy store: real detector policy is tenant-scoped and lives
   * in the control plane, so a `[vars]` entry could only ever be a
   * per-deployment default. See {@link deterministicManagedActionGuardrails}.
   */
  FG_DEV_MCP_GUARDRAILS?: string;

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
   * R2 bucket holding the bytes of every hosted asset. Read as `env.ASSETS`
   * by {@link resolvePorts} — the same binding name and the same bucket
   * `apps/gateway/wrangler.toml` declares. {@link D1R2AssetReader} fetches
   * the object at `storage_uri` from this bucket.
   *
   * OPTIONAL, and its absence is a graceful degradation: {@link resolvePorts}
   * uses {@link InMemoryAssets} when either this or {@link TENANT_DB} is absent,
   * or when `FG_DEV_IN_MEMORY_PORTS === "1"` selects the dev posture, so
   * offline / test environments continue to work with the in-memory store.
   *
   * NOTE: the live account (ferrogate) has R2 unactivated. A deploy with this
   * binding against an account without the R2 plan fails with error 10042.
   * Activate R2 on the account before deploying this Worker.
   */
  ASSETS?: R2Bucket;

  /**
   * D1 database holding the tenant-scoped `stored_assets` /
   * `asset_channels` tables (`sql/d1-ts/tenant/0001_init_tenant.sql`).
   * Read as `env.TENANT_DB` by {@link resolvePorts} — a SEPARATE binding
   * from `env.DB` (the CONTROL database), because this Worker already binds
   * `DB` for the control-plane tables.
   *
   * {@link D1R2AssetReader} queries this database for asset metadata before
   * fetching the object body from {@link ASSETS}. The tenant database is a
   * FLAT binding — tenant isolation is provided by the `WHERE tenant_id = ?1`
   * predicate on every query, exactly as `apps/gateway`'s
   * `D1AssetMetadataStore` works. There is no per-tenant database routing for
   * this reader: when selected, {@link D1R2AssetReader} receives the flat
   * `TENANT_DB` binding directly, and the MCP Worker reads no routing variable
   * for the asset surface.
   *
   * OPTIONAL, and its absence is a graceful degradation: {@link resolvePorts}
   * uses {@link InMemoryAssets} when either this or {@link ASSETS} is absent,
   * or when `FG_DEV_IN_MEMORY_PORTS === "1"` selects the dev posture, so
   * offline / test environments continue to work with the in-memory store.
   */
  TENANT_DB?: D1Database;

  /**
   * The SHARED rate-limit counter namespace — `apps/gateway`'s
   * `RateLimiterDurableObject`, bound here CROSS-SCRIPT.
   *
   * This is what makes the admission gate's RPM window one budget across every
   * FerroGate surface rather than one budget per Worker. A per-Worker counter
   * would hand each surface a full quota, which is a different bug from the one
   * `src/admission/` closes — see the wiring block in `src/admission/index.ts`
   * for the exact `[[durable_objects.bindings]]` stanza (with `script_name`,
   * and deliberately WITHOUT a `[[migrations]]` entry: the class belongs to the
   * gateway script, which already declares it under `new_sqlite_classes`).
   *
   * OPTIONAL, and its absence is a stated degradation rather than a failure:
   * `limiterForEnv` falls back to a per-isolate counter, so the RPM leg becomes
   * 60·N across N isolates while the quota-scope, budget and wallet legs stay
   * fully durable.
   */
  RATE_LIMIT?: RateLimiterNamespace;

  /**
   * Durable Object namespace holding the SHARED upstream-MCP session — the
   * Cloudflare shape of Rust's `McpManager` HashMap (`src/session.ts`). One
   * instance per `(tenant, server)`, so the negotiated protocol revision, the
   * discovered tool list and the connection health are fleet-wide facts rather
   * than per-isolate ones.
   *
   * OPTIONAL, and its absence is a graceful degradation rather than a failure:
   * {@link resolveUpstreams} builds `HttpMcpUpstreams` without a store, which
   * falls back to the per-isolate session map — more handshakes, no shared
   * health signal, same answers.
   */
  MCP_SESSION?: DurableObjectNamespace<FerroGateMcpSession>;

  /**
   * Durable Object namespace holding the UNIFIED CLIENT session (#687,
   * `src/unified.ts`). One instance per `(tenant, client session id)` — the
   * other axis from {@link MCP_SESSION}, which is per `(tenant, UPSTREAM)`.
   *
   * It holds what one client conversation sees: which upstreams its fan-out is
   * bound to, which of them dropped, and the bounded log of emitted frames a
   * `Last-Event-ID` reconnect replays from.
   *
   * OPTIONAL. Absent, the ingress mints no session and answers exactly as it
   * did before this slice — but it then REFUSES an `Mcp-Session-Id` or a
   * `Last-Event-ID` rather than accepting one it cannot honour. Silently
   * ignoring a resume cursor is the failure mode; offering no sessions is a
   * visible degradation.
   */
  MCP_CLIENT_SESSION?: DurableObjectNamespace<FerroGateMcpUnifiedSession>;

  /**
   * DEV/TEST ONLY. When `"1"`, the dev bundle resolves upstreams through the
   * DURABLE path ({@link resolveUpstreams}) instead of the in-memory host.
   *
   * It exists because the two postures are otherwise mutually exclusive in a
   * test: `FG_DEV_IN_MEMORY_PORTS` is what binds an authenticable API key, and
   * without an authenticable key nothing reaches the tool chokepoint at all
   * (see the AuthPort marker on {@link portsBound}). Without this var the
   * production upstream path could only ever be tested through its own
   * constructor — which is exactly the "implemented, tested, never mounted"
   * defect, since a test that builds its own host proves nothing about the app
   * the Worker exports.
   */
  FG_DEV_MCP_DURABLE_UPSTREAMS?: string;

  /**
   * 32-byte AEAD key (base64 or hex) the stored grants are sealed under —
   * the Rust `FERROGATE_MCP_IDENTITY_KEY`.
   *
   * // PORT-TODO(L: inventory-edge-control §MCP): PLATFORM LIMIT — CF bindings,
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

/**
 * The in-memory bundle's lifecycle default.
 *
 * Deliberately NOT the fail-closed {@link UnboundLifecycleGate}: this value is
 * only ever reached by a hand-built bundle in a unit test, which has no control
 * database and no tenancy to gate, and refusing there would make every such
 * test a 503. Every DEPLOYED posture is chosen by {@link resolvePorts}, which
 * never returns this object's `lifecycle` field.
 */
const ALWAYS_ADMIT_LIFECYCLE: TenancyLifecycleGatePort = {
  // eslint-disable-next-line @typescript-eslint/require-await
  async admit() {
    return { admitted: true } as const;
  },
};

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
    // The singleton default admits everything; `resolvePorts` overrides it in
    // every posture, so the deployed Worker's gate is never this one. It exists
    // only so a unit test that builds the bundle by hand is not forced to
    // provide a quota backend.
    admission: ADMIT_ALL,
    // Same reasoning as `admission` above, and the same guarantee: the deployed
    // Worker's lifecycle gate is NEVER this one, because `resolvePorts`
    // overrides it in every posture (`env.DB` is bound in all of them, and the
    // no-database posture gets `UnboundLifecycleGate`, which refuses). It
    // exists so a unit test that builds the bundle by hand is not forced to
    // provide a control database.
    lifecycle: ALWAYS_ADMIT_LIFECYCLE,
    // Same reasoning again, and the same guarantee: `resolvePorts` overrides
    // `rbac` in every posture, so the deployed Worker's authorizer is never
    // this one. The unbound default REFUSES (503) rather than admitting,
    // because an operation that declares an `rbac_action` cannot be authorized
    // with no grant graph to read — see `./rbac.ts`.
    rbac: new UnboundRbacAuthorizer(),
    entitlements: new InMemoryEntitlements(),
    upstreams: new InMemoryUpstreams(),
    // The singleton default is an UNCONFIGURED detector — it matches nothing,
    // which is Rust's answer when no managed-action policy is registered.
    // `resolvePorts` overrides it per request from the operator var, so the
    // deployed Worker's guardrail is never this one.
    guardrails: deterministicManagedActionGuardrails({}),
    approvals: new AutoApproval(),
    assets: new InMemoryAssets(),
    credentials: new InMemoryCredentialStore(),
    oauth: unboundOauthProvider(),
    secrets: unresolvableSecrets(),
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
  secretResolverOverride = undefined;
  ports.secrets = unresolvableSecrets();
}

/** Replace the OAuth provider seam (tests bind a deterministic fake here). */
export function setOauthProvider(provider: OauthProviderPort): void {
  inMemoryPorts().oauth = provider;
}

/**
 * A test-only override for the secret seam, consulted by {@link resolvePorts}
 * ahead of {@link workerSecretResolver}.
 *
 * It is a module-level slot rather than a mutation of {@link inMemoryPorts} so
 * that "a test installed a fake" and "nothing is bound" are DISTINGUISHABLE.
 * Without that distinction the real registry could only ever be bound in a
 * posture no test reaches, and the mount would be unprovable — which is how the
 * previous `{ resolve: async () => undefined }` default survived unnoticed.
 */
let secretResolverOverride: SecretResolverPort | undefined;

/** Replace the secret resolver seam (tests bind a deterministic fake here). */
export function setSecretResolver(resolver: SecretResolverPort): void {
  secretResolverOverride = resolver;
  inMemoryPorts().secrets = resolver;
}

/** The placeholder held on the in-memory bundle when no override is installed. */
function unresolvableSecrets(): SecretResolverPort {
  return { resolve: async () => undefined };
}

/**
 * The REAL secret seam: `@ferrogate/secrets`' `SecretResolverRegistry`, reading
 * THIS Worker's `env`.
 *
 * Every `secret_ref` an operator can write in an upstream's
 * {@link McpOauthConfig.clientSecretRef} goes through it:
 *
 *  - `env://NAME` — a `[vars]` entry, a `wrangler secret put` value, or a
 *    `[[secrets_store_secrets]]` binding (awaited via `SecretsStoreSecret.get()`);
 *  - `cf://<store>/<name>` — the `FERROGATE_CF_SECRET_<NAME>` binding
 *    convention, with the lossy-name ambiguity guard that refuses rather than
 *    serve a credential the operator did not name;
 *  - `vault://<mount>/<path>#<field>` — HashiCorp Vault KV v2, when
 *    `VAULT_ADDR` + `VAULT_TOKEN` are bound.
 *
 * WHY THIS EXISTS: until this mount, `resolvePorts` bound
 * `{ resolve: async () => undefined }` in EVERY posture, so a per-user-OAuth
 * upstream carrying a `client_secret_ref` could never complete a token exchange
 * on a deployed Worker — every authorize/refresh answered
 * `mcp_identity_secret_unavailable` — while `@ferrogate/secrets` sat fully
 * implemented and fully tested with zero importers in any app. The registry is
 * built LAZILY (first `resolve`) so an upstream with no `client_secret_ref`
 * never pays for it, and so a malformed backend configuration surfaces on the
 * request that needs the secret rather than on every request.
 *
 * `McpEnv` is cast to `EnvLike` because a Worker `env` is heterogeneous — it
 * also carries KV/D1/DO namespaces. That is safe: the registry only ever reads
 * the specific NAMES a secret reference or a backend variable asks for, and
 * `isSecretsStoreBinding` refuses any slot that looks like another binding.
 */
export function workerSecretResolver(env: McpEnv): SecretResolverPort {
  let registry: SecretResolverRegistry | undefined;
  return {
    async resolve(reference: string): Promise<string | undefined> {
      registry ??= SecretResolverRegistry.fromEnv(env as unknown as EnvLike);
      // The registry's `null` is "not configured"; the port's `undefined` means
      // the same thing to `resolveClientSecret`. A genuine failure (ambiguous
      // `cf://` name, Vault unreachable, unparseable reference) THROWS, and the
      // caller turns it into `mcp_identity_secret_unavailable` with the reason
      // attached rather than a bare 500.
      return (await registry.resolve(reference)) ?? undefined;
    },
  };
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
 * PORT-TODO(L: inventory-edge-control §MCP): the Rust implementation seals stored
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
 * Whether the deploy-time binding the DURABLE {@link AuthPort} needs is present.
 *
 * One binding, because the credential tables `src/auth.ts` reads —
 * `static_api_keys` and `api_key_directory` — live in the CONTROL database this
 * Worker already binds as `env.DB` (`wrangler.toml`,
 * `database_name = "ferrogate-control"`). The per-tenant databases the NATIVE
 * leg's second hop needs are resolved by NAME at runtime through
 * `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter`, so they are not part
 * of this predicate: a deployment with no tenant bindings still authenticates
 * operator/static keys and refuses virtual ones with a 401, which is a partial
 * capability rather than an unready Worker.
 */
export function durableAuthBound(env: McpEnv): boolean {
  return env.DB !== undefined;
}

/**
 * Whether this Worker has a usable port bundle for authenticated traffic.
 *
 * This is the single source of truth {@link resolvePorts} branches on, so
 * `/readyz` cannot claim readiness on an isolate whose auth port is
 * {@link UnboundAuth} — the Workers equivalent of the Rust readiness probe
 * reporting `not_ready` while the cluster has no healthy peer.
 *
 * MARKER CLOSED (was: "the last port with no durable implementation is
 * `AuthPort` … binding it means either a `[[services]]` service binding to
 * `apps/control-plane` or a shared D1 read of its `api_keys` table"). It was
 * the SECOND of those, and it needed no new binding: `env.DB` already IS the
 * control database, so `D1McpAuth` (`src/auth.ts`) reads `static_api_keys`,
 * `api_key_directory` and the tenant-routed `api_keys` row directly. A
 * production Worker that correctly refuses to set `FG_DEV_IN_MEMORY_PORTS` is
 * therefore READY and authenticates real credentials, where before it answered
 * `503 mcp_auth_unavailable` on every authenticated surface forever.
 */
export function portsBound(env: McpEnv): boolean {
  return env.FG_DEV_IN_MEMORY_PORTS === "1" || durableAuthBound(env);
}

/**
 * Decode {@link McpEnv.FG_DEV_MCP_GUARDRAILS}.
 *
 * Absent, empty, or unparseable ⇒ `{}` ⇒ NO detector, which matches nothing.
 * That is deliberate and is the same fallback `apps/agent-runtime` uses for its
 * A2A var: a `[vars]` entry is a per-deployment default, and a typo in it must
 * not become a guardrail that refuses every call. A typo in the OTHER direction
 * — silently disabling a configured guardrail — is the risk this trades
 * against, which is why the real enforcement policy is tenant-scoped control-
 * plane state and this var is DEV/TEST ONLY.
 */
export function parseGuardrailVar(raw: string | undefined): ManagedActionGuardrailConfig {
  if (raw === undefined || raw.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed as ManagedActionGuardrailConfig;
  } catch {
    return {};
  }
}

/**
 * Resolve the port bundle for a request.
 *
 * Three postures, in order:
 *
 *  1. **dev bundle** (`FG_DEV_IN_MEMORY_PORTS === "1"`) — everything in memory,
 *     EXCEPT that the durable auth leg still runs FIRST when `env.DB` is bound
 *     (see below).
 *  2. **durable identity** — D1 + KV + key material bound: the credential store
 *     and cipher are the real, isolate-surviving implementations, so a revoked
 *     grant stays revoked and an OAuth callback that lands on a different
 *     isolate than the one that began the flow still completes.
 *  3. **nothing bound** — fail closed with {@link UnboundAuth}.
 *
 * The AUTH PORT is bound to {@link D1McpAuth} in every posture where `env.DB`
 * exists, including the dev one, and that is deliberate on two counts:
 *
 *  * **Order.** The durable row is consulted BEFORE the in-memory dev table,
 *    which is passed as its fallback. A stale dev key therefore can never
 *    re-enable a credential the control database revoked, and the fallback is
 *    reached only for a credential no durable table knows.
 *  * **Provability.** The dev bundle is the only posture the offline suite can
 *    drive end to end over `SELF`, so binding the durable authenticator only in
 *    the non-dev posture would leave the mount testable exclusively through its
 *    own constructor — which is the "implemented, tested, never mounted" defect
 *    this project keeps being bitten by. `test/d1-auth.test.ts` seeds real rows
 *    into the real `env.DB` and drives the REAL Worker; deleting the
 *    `auth: durableAuth(env)` line below turns that suite RED.
 *
 * Within posture 2 the flow store is chosen by capability, not by config: when
 * {@link McpEnv.MCP_OAUTH_FLOWS} is bound the single-use claim is the ATOMIC
 * Durable-Object one, and only a deployment missing that binding degrades to
 * KV's non-indivisible `get`+`delete`.
 *
 * The GUARDRAIL is bound in EVERY posture, including the fail-closed one. It is
 * this Worker's composition root for {@link durableManagedActionGuardrails}
 * over {@link deterministicManagedActionGuardrails}, so dropping the binding
 * here silently un-scans every MCP tool argument and every tool result while
 * leaving the whole suite green — the exact defect `test/guardrails.test.ts`
 * (the var half) and `test/fleet-guardrail-activation.test.ts` (the DURABLE
 * half, FC-3) drive over `SELF` to prevent.
 *
 * The SECRET SEAM is bound in EVERY posture for the same reason: an upstream's
 * `client_secret_ref` must resolve wherever the OAuth exchange can run, and the
 * dev bundle is the only posture the offline suite can drive end to end, so
 * binding it anywhere else would leave the mount unprovable. `secrets` is
 * {@link workerSecretResolver} unless a test installed an override through
 * {@link setSecretResolver}. Dropping this binding silently returns the Worker
 * to answering `mcp_identity_secret_unavailable` for every configured upstream
 * credential — `test/secrets-mount.test.ts` drives that over `SELF`.
 */
export function resolvePorts(env: McpEnv): McpPorts {
  // FC-3. The DURABLE activated revision runs FIRST and the operator var is its
  // fallback, so an activated `guardrail_policy_bindings` row screens MCP tool
  // arguments and tool results on the very next call — no redeploy, no cache to
  // flush — while a var-only deployment behaves exactly as it did. Dropping the
  // wrapper here silently returns this Worker to the state
  // `docs/rewrite/FLEET-CONSISTENCY.md` FC-3 describes: an operator activates a
  // policy, sees it bound, and it covers one of three doors.
  const guardrails = durableManagedActionGuardrails(
    env,
    deterministicManagedActionGuardrails(parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS)),
  );
  const secrets = secretResolverOverride ?? workerSecretResolver(env);
  const auth = durableAuth(env);
  const approvals = durableApprovals(env);
  const admission = durableAdmission(env);
  const lifecycle = durableLifecycle(env);
  // FC-7. THE MOUNT of the RBAC gate. Deleting this line returns the Worker to
  // the state FLEET-CONSISTENCY records: `rbac_action` parsed off the contract
  // and never read, so a role an operator uses to withhold an action is
  // enforced on `apps/gateway` and silently ignored here.
  const rbac = rbacAuthorizerFromEnv(env);
  const entitlements = durableEntitlements(env);
  // Asset reader: D1+R2 when both bindings are present, InMemoryAssets otherwise.
  // NOTE: NOT bound in the dev posture — the dev posture uses InMemoryAssets from
  // inMemoryPorts(). The D1R2AssetReader is only selected in the non-dev posture
  // (env.FG_DEV_IN_MEMORY_PORTS !== "1"), because the dev posture is the offline
  // test environment where R2 and the tenant D1 are not guaranteed to be present.
  // The mount is tested directly through D1R2AssetReader unit tests and through
  // the e2e test that seeds D1+R2 and drives SELF.fetch. Deleting the `assets`
  // line below turns `test/d1-r2-asset-reader.test.ts` red.
  const assets: AssetReaderPort =
    env.ASSETS !== undefined && env.TENANT_DB !== undefined
      ? new D1R2AssetReader(env.TENANT_DB, env.ASSETS)
      : inMemoryPorts().assets;
  if (env.FG_DEV_IN_MEMORY_PORTS === "1")
    return {
      ...inMemoryPorts(),
      guardrails,
      secrets,
      auth,
      approvals,
      admission,
      lifecycle,
      rbac,
      entitlements,
    };
  const ports = {
    ...inMemoryPorts(),
    guardrails,
    secrets,
    auth,
    approvals,
    admission,
    lifecycle,
    rbac,
    entitlements,
    assets,
  };
  if (durableIdentityBound(env)) {
    return {
      ...ports,
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
  return ports;
}

/**
 * Choose the {@link AuthPort} for this env.
 *
 * `env.DB` bound ⇒ {@link D1McpAuth} over the CONTROL database, with
 * `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter` for the NATIVE leg's
 * second hop and — in the dev posture only — the in-memory table as fallback.
 * No `env.DB` ⇒ {@link UnboundAuth}, which is a 503 and never an open door.
 *
 * The router is constructed here rather than inside `D1McpAuth` so the class
 * stays testable against a stub, and so this file remains the ONE place that
 * decides where a credential is allowed to come from.
 */
/**
 * Choose the {@link ApprovalPort} for this env.
 *
 * `env.DB` bound ⇒ {@link D1ToolApprovals} over the shared `tool-approvals`
 * queue in the CONTROL database. Absent ⇒ {@link AutoApproval}, which approves
 * EVERYTHING — the honest name for "there is no queue to consult", and the
 * reason the D1 binding is what a real deployment must have.
 *
 * Bound in the dev posture too, for the same provability reason the auth port
 * is: the offline suite can only drive the deployed app end to end there, so a
 * gate mounted anywhere else would be untestable over `SELF`.
 */
function durableApprovals(env: McpEnv): ApprovalPort {
  if (env.DB === undefined) return new AutoApproval();
  return new D1ToolApprovals(env.DB);
}

function durableAuth(env: McpEnv): AuthPort {
  if (env.DB === undefined) return new UnboundAuth();
  const options: D1McpAuthOptions = {
    router: new EnvBindingTenantDatabaseRouter(env as unknown as Record<string, unknown>, env.DB),
  };
  return new D1McpAuth(
    env.DB,
    env.FG_DEV_IN_MEMORY_PORTS === "1" ? { ...options, fallback: inMemoryPorts().auth } : options,
  );
}

/**
 * Choose the {@link AdmissionPort} for this env — the ADMISSION half of Rust's
 * `authenticate()`.
 *
 * `env.DB` bound ⇒ the real ladder: the CONTROL database's `quota_policies` +
 * `plans` chain merged by `@ferrogate/policy`, the tenant-routed
 * `usage_monthly_rollups` / `wallets` spend store, and the RPM window on the
 * SHARED `RATE_LIMIT` namespace when one is bound. Absent ⇒ `ADMIT_ALL`, the
 * honest reading of "this deployment has no `quota_policies` table, so no
 * policy could have been configured" — which is why binding `DB` can only ever
 * TIGHTEN admission.
 *
 * Bound in the DEV posture too, for the same provability reason the auth port
 * is: the offline suite can only drive the deployed app end to end there, so a
 * gate mounted anywhere else would be untestable over `SELF` — the
 * "implemented, tested, never mounted" defect this project keeps repeating.
 * Deleting the `admission` line in {@link resolvePorts} turns
 * `test/admission.test.ts` red.
 *
 * The router is the SAME construction `durableAuth` uses, so the credential and
 * its spend are always read out of one tenant's database.
 */
/**
 * Choose the {@link TenancyLifecycleGatePort} for this env — the control an
 * operator applies once and every spending Worker must honour (FC-2).
 *
 * `env.DB` bound ⇒ {@link D1McpTenancyLifecycleGate} over `tenants.status` in
 * the CONTROL database — the SAME rows `apps/gateway` reads and
 * `apps/control-plane`'s lifecycle routes write — with the tenant-routed
 * database supplying the `projects` / `workspaces` tiers of the walk. Absent ⇒
 * {@link UnboundLifecycleGate}, a 503 and never an open door.
 *
 * The router is the SAME construction `durableAuth` and `durableAdmission` use,
 * so a credential, its spend and its tenancy status are always read out of one
 * tenant's database.
 *
 * Bound in the DEV posture too, for the provability reason the other two ports
 * state: the offline suite can only drive the deployed app end to end there, so
 * a gate mounted anywhere else would be untestable over `SELF` — the
 * "implemented, tested, never mounted" defect this project keeps repeating.
 * Deleting the `lifecycle` entry in {@link resolvePorts} turns
 * `test/fleet-tenancy-suspension.test.ts` red.
 */
function durableLifecycle(env: McpEnv): TenancyLifecycleGatePort {
  if (env.DB === undefined) return new UnboundLifecycleGate();
  return new D1McpTenancyLifecycleGate(
    env.DB,
    new EnvBindingTenantDatabaseRouter(env as unknown as Record<string, unknown>, env.DB),
  );
}

function durableAdmission(env: McpEnv): AdmissionPort {
  if (env.DB === undefined) return ADMIT_ALL;
  return admissionFromEnv(
    env,
    new EnvBindingTenantDatabaseRouter(env as unknown as Record<string, unknown>, env.DB),
  );
}

/**
 * Choose the {@link EntitlementPort} for this env — the PLAN-and-RBAC tool
 * entitlement ladder (`docs/rewrite/CUTOVER-READINESS.md` finding **A3/R1**,
 * cluster **S5**).
 *
 * `env.DB` bound ⇒ {@link D1ToolEntitlements} over the CONTROL database's
 * `tenants` × `plans` × `permissions` × `roles` × `tenant_role_bindings` — the
 * SAME rows `apps/control-plane`'s plan and RBAC routes write. Absent ⇒
 * {@link InMemoryEntitlements}, which denies nobody: that is the honest reading
 * of "this deployment has no `plans` table, so no plan could have withdrawn
 * anything", AND it is the posture Rust itself lands in when the control plane
 * is unreadable (`tenant_account_exists && …` with every lookup swallowing its
 * error). Binding `DB` can therefore only ever TIGHTEN entitlement.
 *
 * The dev bundle is passed as the FALLBACK, not as the answer: it speaks only
 * for a tenant with no `tenants` row, so a real plan can never be overridden by
 * it. Production sets no `FG_DEV_IN_MEMORY_PORTS` and gets no fallback at all.
 *
 * Bound in the DEV posture too, for the same provability reason the auth,
 * admission and lifecycle ports state: the offline suite can only drive the
 * deployed app end to end there, so a gate mounted anywhere else would be
 * untestable over `SELF` — the "implemented, tested, never mounted" defect that
 * is precisely what R1 turned out to be. Deleting the `entitlements` entry in
 * {@link resolvePorts} turns `test/entitlements.test.ts` red.
 */
function durableEntitlements(env: McpEnv): EntitlementPort {
  if (env.DB === undefined) return inMemoryPorts().entitlements;
  return new D1ToolEntitlements(
    env.DB,
    env.FG_DEV_IN_MEMORY_PORTS === "1" ? { fallback: inMemoryPorts().entitlements } : {},
  );
}
