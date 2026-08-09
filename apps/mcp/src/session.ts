/**
 * The SHARED upstream-MCP session manager — the Cloudflare shape of Rust's
 * `McpManager`.
 *
 * ## What this closes
 *
 * `crates/ferrogate-mcp/src/manager.rs` keeps a process-wide
 * `HashMap<name, Arc<Mutex<McpSession>>>`: one live session per configured
 * upstream, holding the negotiated protocol revision, the discovered tool list
 * and the connection health (`connected`, `last_error`, `reconnect_attempts`,
 * `last_connected_at_unix`, `next_reconnect_backoff_secs`), plus a
 * `health_check_and_reconnect()` the gateway loop drives.
 *
 * A Worker has no process to hang that map on. `HttpMcpUpstreams` therefore
 * held it per ISOLATE, which re-ran the handshake on every cold isolate and
 * meant an upstream outage was discovered once per isolate instead of once
 * globally. That was recorded as `PORT_TODO(inventory-edge-control §MCP
 * "session manager")` and explicitly NOT as a platform limit: Cloudflare has
 * the primitive.
 *
 * This module is that primitive. {@link FerroGateMcpSession} is ONE Durable
 * Object per `(tenant, server)` upstream, addressed with `idFromName`, so every
 * isolate serving a tenant reaches the SAME single-threaded actor and observes
 * the same session state. {@link DurableMcpSessionStore} is the seam
 * `HttpMcpUpstreams` talks to.
 *
 * ## What is faithfully ported, and what deliberately is not
 *
 * PORTED, transition for transition, from `McpSession`:
 *  - {@link FerroGateMcpSession.connected} = the `Ok(())` arm of
 *    `connect_or_record_error` / `try_reconnect`: `connected = true`,
 *    `last_error = None`, `reconnect_attempts = 0`,
 *    `next_reconnect_backoff_secs = min_reconnect_backoff_secs`,
 *    `last_connected_at_unix = now`.
 *  - {@link FerroGateMcpSession.failed} = the `Err` arm of `try_reconnect`:
 *    `connected = false`, the client and the TOOL LIST are dropped,
 *    `last_error` is set, `reconnect_attempts` increments (saturating), and
 *    `next_reconnect_backoff_secs = min(previous * 2, max_reconnect_backoff_secs)`.
 *  - {@link FerroGateMcpSession.unhealthy} = the failed-probe arm of
 *    `health_check_and_reconnect`: `connected = false` with the literal
 *    `MCP health check failed`, WITHOUT clearing the tools or touching the
 *    backoff — Rust clears those only when a reconnect attempt then fails.
 *
 * NOT ported, on purpose:
 *  - `next_reconnect_backoff_secs` is REPORTED, never slept on. Rust never
 *    slept on it either (`try_reconnect` loops without a delay); it is status
 *    the operator surface reads. Turning it into an admission gate here would
 *    be a behavior change dressed up as a port.
 *  - The JSON-RPC request-id counter stays ISOLATE-LOCAL. Routing it through
 *    the DO would add a round trip to every upstream call to buy nothing: over
 *    HTTP the id only has to distinguish the in-flight requests of one
 *    connection, and two isolates hold two connections.
 *  - `stdio` sessions get no DO. They cannot connect at all on Workers (no
 *    process spawn — see `transport.ts`), so there is no session to share.
 */
import { DurableObject } from "cloudflare:workers";

import type { McpTool } from "./ports.js";
import type { McpNegotiatedProtocol } from "./protocol.js";

/**
 * Rust `McpServerConfig`'s reconnect knobs. Defaults are
 * `DEFAULT_MAX_RECONNECT_ATTEMPTS` (5), `DEFAULT_MIN_RECONNECT_BACKOFF_SECS`
 * (1) and `DEFAULT_MAX_RECONNECT_BACKOFF_SECS` (30) from
 * `crates/ferrogate-mcp/src/config.rs`.
 */
export interface McpReconnectPolicy {
  readonly maxReconnectAttempts: number;
  readonly minReconnectBackoffSecs: number;
  readonly maxReconnectBackoffSecs: number;
}

/** The Rust defaults, verbatim. */
export const DEFAULT_RECONNECT_POLICY: McpReconnectPolicy = {
  maxReconnectAttempts: 5,
  minReconnectBackoffSecs: 1,
  maxReconnectBackoffSecs: 30,
};

/**
 * The shared per-upstream session record — Rust `McpSession`'s fields, minus
 * the live `client` handle (a socket cannot be shared across isolates; the
 * NEGOTIATION is what is worth sharing, and it is re-usable by construction).
 */
export interface McpSessionState {
  connected: boolean;
  negotiation?: McpNegotiatedProtocol;
  tools: McpTool[];
  lastError?: string;
  reconnectAttempts: number;
  lastConnectedAtUnix?: number;
  nextReconnectBackoffSecs: number;
}

/** Rust `McpServerStatus`, as this port can populate it. */
export interface McpServerStatus {
  name: string;
  connected: boolean;
  /** Rust's literal two-valued health string. */
  health: "ok" | "degraded";
  tools: number;
  reconnectAttempts: number;
  lastError?: string;
  lastConnectedAtUnix?: number;
  nextReconnectBackoffSecs: number;
  protocolVersion?: string;
  protocolMode?: McpNegotiatedProtocol["mode"];
  protocolDowngradeReason?: McpNegotiatedProtocol["downgradeReason"];
}

/** Rust `McpSession::new`. */
export function newSessionState(policy: McpReconnectPolicy): McpSessionState {
  return {
    connected: false,
    tools: [],
    reconnectAttempts: 0,
    nextReconnectBackoffSecs: policy.minReconnectBackoffSecs,
  };
}

/** Rust `McpSession::status`. `protocol_*` are `None` while disconnected. */
export function statusOf(name: string, state: McpSessionState): McpServerStatus {
  const status: McpServerStatus = {
    name,
    connected: state.connected,
    health: state.connected ? "ok" : "degraded",
    tools: state.tools.length,
    reconnectAttempts: state.reconnectAttempts,
    nextReconnectBackoffSecs: state.nextReconnectBackoffSecs,
  };
  if (state.lastError !== undefined) status.lastError = state.lastError;
  if (state.lastConnectedAtUnix !== undefined) {
    status.lastConnectedAtUnix = state.lastConnectedAtUnix;
  }
  if (state.connected && state.negotiation !== undefined) {
    status.protocolVersion = state.negotiation.version;
    status.protocolMode = state.negotiation.mode;
    if (state.negotiation.downgradeReason !== undefined) {
      status.protocolDowngradeReason = state.negotiation.downgradeReason;
    }
  }
  return status;
}

/** The storage key each instance holds. */
const STATE_KEY = "session";

/** Rust's literal health-check failure string. */
export const HEALTH_CHECK_FAILED = "MCP health check failed";

/**
 * One shared upstream MCP session, addressed by
 * `idFromName(sessionKey(tenantId, serverName))`.
 *
 * Sharding per `(tenant, server)` rather than one manager object for
 * everything is what keeps this contention-free: Rust took a per-session
 * `Mutex`, and a single global actor would serialize every tenant's upstream
 * traffic behind one another's.
 *
 * Storage is the DO's own embedded SQLite (`new_sqlite_classes`). One record
 * per instance, so a read is a point lookup.
 */
export class FerroGateMcpSession extends DurableObject {
  /** The session as it stands. Never `undefined` — an unseen upstream is new. */
  async read(policy: McpReconnectPolicy): Promise<McpSessionState> {
    const stored = await this.ctx.storage.get<McpSessionState>(STATE_KEY);
    return stored ?? newSessionState(policy);
  }

  /**
   * A handshake SUCCEEDED — Rust's `Ok(())` arm.
   *
   * The whole transition runs inside `blockConcurrencyWhile` so a concurrent
   * `failed()` from another isolate cannot interleave between the read and the
   * write and leave a half-applied record (connected with a stale error, or a
   * doubled backoff on a healthy session).
   */
  async connected(
    negotiation: McpNegotiatedProtocol,
    tools: McpTool[],
    nowUnix: number,
    policy: McpReconnectPolicy,
  ): Promise<McpSessionState> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.read(policy);
      const next: McpSessionState = {
        ...state,
        connected: true,
        negotiation,
        tools,
        reconnectAttempts: 0,
        nextReconnectBackoffSecs: policy.minReconnectBackoffSecs,
        lastConnectedAtUnix: nowUnix,
      };
      // `last_error = None`: an exact delete, not `undefined`, so the record
      // does not carry a stale failure past a recovery.
      // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
      delete next.lastError;
      await this.ctx.storage.put(STATE_KEY, next);
      return next;
    });
  }

  /**
   * A connect attempt FAILED — Rust's `Err` arm of `try_reconnect`.
   *
   * The tool list is dropped with the connection. That is deliberate in Rust
   * and load-bearing here: a tool list is an allowlisted capability set, and
   * continuing to advertise tools of an upstream that is refusing connections
   * would let a caller be denied at execution time by a server the catalog
   * still claims is live.
   */
  async failed(message: string, policy: McpReconnectPolicy): Promise<McpSessionState> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.read(policy);
      const next: McpSessionState = {
        ...state,
        connected: false,
        tools: [],
        lastError: message,
        // `saturating_add`: a permanently-down upstream must not wrap the
        // counter back to a number that reads as healthy.
        reconnectAttempts: Math.min(state.reconnectAttempts + 1, Number.MAX_SAFE_INTEGER),
        nextReconnectBackoffSecs: Math.min(
          state.nextReconnectBackoffSecs * 2,
          policy.maxReconnectBackoffSecs,
        ),
      };
      // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
      delete next.negotiation;
      await this.ctx.storage.put(STATE_KEY, next);
      return next;
    });
  }

  /**
   * The health PROBE failed — the first half of Rust
   * `health_check_and_reconnect`.
   *
   * Note what is NOT touched: the tool list and the backoff. Rust clears those
   * only once a reconnect attempt has also failed, so a transient probe miss
   * on an upstream that reconnects immediately does not blank the catalog.
   */
  async unhealthy(policy: McpReconnectPolicy): Promise<McpSessionState> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.read(policy);
      const next: McpSessionState = {
        ...state,
        connected: false,
        lastError: HEALTH_CHECK_FAILED,
      };
      await this.ctx.storage.put(STATE_KEY, next);
      return next;
    });
  }

  /** Rust `McpManager::reconfigure` — a config change drops the old session. */
  async reset(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

/**
 * The seam `HttpMcpUpstreams` uses. Kept as an interface so the transport can
 * be exercised with an in-memory store and so a deployment WITHOUT the
 * `MCP_SESSION` binding degrades to the per-isolate map rather than failing.
 */
export interface McpSessionStorePort {
  read(serverName: string): Promise<McpSessionState>;
  connected(
    serverName: string,
    negotiation: McpNegotiatedProtocol,
    tools: McpTool[],
    nowUnix: number,
  ): Promise<McpSessionState>;
  failed(serverName: string, message: string): Promise<McpSessionState>;
  unhealthy(serverName: string): Promise<McpSessionState>;
  reset(serverName: string): Promise<void>;
}

/**
 * The DO address for one upstream.
 *
 * The tenant id is part of the name, so two tenants configuring an upstream
 * with the SAME `name` never share a session — the cross-tenant isolation
 * property, enforced by addressing rather than by a check that can be
 * forgotten. `\0` separates the fields because it cannot appear in either.
 */
export function sessionKey(tenantId: string, serverName: string): string {
  return `${tenantId}\0${serverName}`;
}

/**
 * The RPC surface {@link DurableMcpSessionStore} invokes on a stub.
 *
 * Written out by hand instead of being read off
 * `DurableObjectStub<FerroGateMcpSession>`, for a concrete compiler reason:
 * `McpTool.inputSchema` is `JsonValue`, which is RECURSIVE, and the workers
 * runtime types map a stub's methods through `Rpc.Provider` structurally. Doing
 * that over a recursive argument type makes tsc give up with TS2589 ("type
 * instantiation is excessively deep and possibly infinite"), which is a HARD
 * typecheck failure for the whole app, not a warning.
 *
 * The hazard of hand-writing it is drift — a signature changing on the class
 * while this copy keeps compiling against the old one. {@link
 * FerroGateMcpSessionImplementsRpc} closes that: it is a type-level assertion
 * that the CLASS is assignable to this interface, so renaming a method,
 * dropping a parameter or changing a return type on `FerroGateMcpSession` fails
 * `tsc --noEmit` here rather than at runtime on a deployed stub.
 */
interface McpSessionRpc {
  read(policy: McpReconnectPolicy): Promise<McpSessionState>;
  connected(
    negotiation: McpNegotiatedProtocol,
    tools: McpTool[],
    nowUnix: number,
    policy: McpReconnectPolicy,
  ): Promise<McpSessionState>;
  failed(message: string, policy: McpReconnectPolicy): Promise<McpSessionState>;
  unhealthy(policy: McpReconnectPolicy): Promise<McpSessionState>;
  reset(): Promise<void>;
}

/**
 * Compile-time proof that {@link McpSessionRpc} still mirrors the DO class.
 *
 * The `T extends U` CONSTRAINT is what does the work — a conditional type would
 * silently evaluate to its false branch and compile. Break a signature on
 * `FerroGateMcpSession` and this line is a TS2344 error.
 */
type Implements<T extends U, U> = T;
export type FerroGateMcpSessionImplementsRpc = Implements<FerroGateMcpSession, McpSessionRpc>;

/** {@link McpSessionStorePort} over the real Durable Object namespace. */
export class DurableMcpSessionStore implements McpSessionStorePort {
  readonly #namespace: DurableObjectNamespace<FerroGateMcpSession>;
  readonly #tenantId: string;
  readonly #policy: McpReconnectPolicy;

  constructor(
    namespace: DurableObjectNamespace<FerroGateMcpSession>,
    tenantId: string,
    policy: McpReconnectPolicy = DEFAULT_RECONNECT_POLICY,
  ) {
    this.#namespace = namespace;
    this.#tenantId = tenantId;
    this.#policy = policy;
  }

  #stub(serverName: string): McpSessionRpc {
    // `idFromName`, NOT `newUniqueId`: a fresh id per isolate would recreate
    // exactly the per-isolate map this class exists to replace.
    const name = sessionKey(this.#tenantId, serverName);
    const stub = this.#namespace.get(this.#namespace.idFromName(name));
    // See {@link McpSessionRpc} for why the stub is narrowed rather than used
    // through its inferred `Rpc.Provider` type.
    return stub as unknown as McpSessionRpc;
  }

  read(serverName: string): Promise<McpSessionState> {
    return this.#stub(serverName).read(this.#policy);
  }

  connected(
    serverName: string,
    negotiation: McpNegotiatedProtocol,
    tools: McpTool[],
    nowUnix: number,
  ): Promise<McpSessionState> {
    return this.#stub(serverName).connected(negotiation, tools, nowUnix, this.#policy);
  }

  failed(serverName: string, message: string): Promise<McpSessionState> {
    return this.#stub(serverName).failed(message, this.#policy);
  }

  unhealthy(serverName: string): Promise<McpSessionState> {
    return this.#stub(serverName).unhealthy(this.#policy);
  }

  reset(serverName: string): Promise<void> {
    return this.#stub(serverName).reset();
  }
}
