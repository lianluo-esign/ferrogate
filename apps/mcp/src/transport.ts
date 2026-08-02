/**
 * MCP transports: Streamable HTTP and SSE, in both directions.
 *
 * Clean-room port of `crates/ferrogate-mcp/src/http_client.rs` (the outbound
 * host client, its 16 MiB response cap, and the incremental `data:` SSE parse
 * that returns on the FIRST complete JSON value rather than blocking on
 * connection close) plus the server side of the Streamable-HTTP contract the
 * FerroGate ingress speaks.
 *
 * PORT-TODO(L: inventory-edge-control §MCP): PLATFORM LIMIT — the stdio transport
 * cannot exist in a Worker. Rust's `stdio_client.rs` spawns a CHILD PROCESS per
 * upstream, writes JSON-RPC to its stdin, reads from its stdout, and owns a
 * `dispatch_cleanup_handle` that kills the child on timeout. workerd has no
 * `fork`/`exec`, no pipes and no process table; there is no API to add and no
 * effort that closes this. The only CF home for a stdio MCP server is a
 * Container / `@cloudflare/sandbox`, which is a different deployment artifact,
 * not a change to this module.
 *
 * IMPLEMENTED INSTEAD: a stdio upstream stays FULLY CONFIGURABLE — the catalog
 * decodes it and `listServers` reports it — and is refused at DISPATCH with
 * `mcp_server_unavailable`. The refusal is deliberate and specific: silently
 * treating a stdio upstream as HTTP would send a local-process server's traffic
 * onto the network, and silently dropping it from the catalog would hide a
 * misconfiguration the operator needs to see. Pinned by
 * `test/upstream-transport.test.ts` ("refuses a stdio dispatch instead of
 * silently treating it as HTTP") and `test/durable-identity.test.ts` ("keeps a
 * stdio row decodable — it is refused at DISPATCH, not at config").
 *
 * NOTE — the server-side ingress USED to be deliberately stateless, and this
 * header used to record that as parity with Rust's `mcp_ingress.rs`, which
 * mints no `Mcp-Session-Id` and keeps no `Last-Event-ID` replay log. #687 says
 * that parity is the defect: a client fanning in to many upstreams loses the
 * WHOLE fan-out on one SSE reconnect. The session and the replay log now live
 * in `src/unified.ts` — a Durable Object per CLIENT session, addressed by
 * `(tenant, session id)` — and this module keeps only the framing they use
 * ({@link sseFrameResponse} emits a replayed run of frames ahead of a fresh
 * one). Everything below is still the OUTBOUND client and the wire framing; the
 * session state deliberately is not here.
 */
import type { JsonValue } from "@ferrogate/core";

import {
  type McpToolExecutionResult,
  type ParsedToolDef,
  callToolParams,
  parseCallResult,
  parseToolsList,
} from "./jsonrpc.js";
import {
  type McpFanIn,
  type McpToolResolution,
  type McpUpstreamFailure,
  candidateServerNames,
  namespacedToolName,
  resolveAcrossCatalog,
} from "./multiplex.js";
import {
  type DispatchContext,
  McpDispatchHeaders,
  McpExecutionError,
  type McpServerConfig,
  type McpTool,
  type McpUpstreamPort,
  toolAllowlisted,
  toolPermitted,
} from "./ports.js";
import {
  FERROGATE_CLIENT_INFO,
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_HEADER,
  type McpNegotiatedProtocol,
  discoverSupportsCurrentVersion,
  encodeMcpHeaderValue,
  httpLegacyDowngradeReason,
  jsonRpcErrorCode,
  modernDiscoverParams,
  modernRequestParams,
  resolveLegacyProtocolVersion,
} from "./protocol.js";
import {
  DEFAULT_RECONNECT_POLICY,
  type McpReconnectPolicy,
  type McpServerStatus,
  type McpSessionState,
  type McpSessionStorePort,
  statusOf,
} from "./session.js";

/** Hard cap on any single upstream response (Rust `MAX_MCP_RESPONSE_BYTES`). */
export const MAX_MCP_RESPONSE_BYTES = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Server side: SSE framing
// ---------------------------------------------------------------------------

/** One `text/event-stream` frame. */
export interface SseEvent {
  event?: string;
  data: string;
  id?: string;
  retry?: number;
}

/**
 * Encode one SSE frame. Multi-line `data` is split across repeated `data:`
 * fields (required by the spec — a raw newline would terminate the event), and
 * the frame is terminated by the blank line that dispatches it.
 */
export function encodeSseEvent(event: SseEvent): string {
  let frame = "";
  if (event.event !== undefined) frame += `event: ${event.event}\n`;
  if (event.id !== undefined) frame += `id: ${event.id}\n`;
  if (event.retry !== undefined) frame += `retry: ${event.retry}\n`;
  for (const line of event.data.split("\n")) frame += `data: ${line}\n`;
  return `${frame}\n`;
}

/** Parse a complete `text/event-stream` document into its dispatched frames. */
export function parseSseEvents(text: string): SseEvent[] {
  const events: SseEvent[] = [];
  let current: { event?: string; data: string[]; id?: string; retry?: number } = { data: [] };
  const flush = (): void => {
    if (current.data.length === 0 && current.event === undefined && current.id === undefined) {
      current = { data: [] };
      return;
    }
    const built: SseEvent = { data: current.data.join("\n") };
    if (current.event !== undefined) built.event = current.event;
    if (current.id !== undefined) built.id = current.id;
    if (current.retry !== undefined) built.retry = current.retry;
    events.push(built);
    current = { data: [] };
  };
  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    if (line.length === 0) {
      flush();
      continue;
    }
    // A `:`-prefixed line is a comment / keep-alive.
    if (line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "event":
        current.event = value;
        break;
      case "data":
        current.data.push(value);
        break;
      case "id":
        current.id = value;
        break;
      case "retry": {
        const retry = Number.parseInt(value, 10);
        if (Number.isFinite(retry)) current.retry = retry;
        break;
      }
      default:
        break;
    }
  }
  flush();
  return events;
}

/**
 * Streamable HTTP lets the server answer a POST with either `application/json`
 * or `text/event-stream`. True when the caller advertised the event stream (and
 * did not restrict itself to JSON).
 */
export function prefersEventStream(accept: string | null): boolean {
  if (accept === null) return false;
  const lowered = accept.toLowerCase();
  if (!lowered.includes("text/event-stream")) return false;
  if (lowered.includes("application/json")) {
    // Both advertised: honour the higher `q` value, defaulting to 1.0. The MCP
    // client SDK sends `application/json, text/event-stream` and is happy with
    // either, so ties go to JSON — the cheaper, non-streaming answer.
    return qualityOf(lowered, "text/event-stream") > qualityOf(lowered, "application/json");
  }
  return true;
}

function qualityOf(accept: string, mediaType: string): number {
  for (const part of accept.split(",")) {
    const [type, ...parameters] = part.trim().split(";");
    if (type?.trim() !== mediaType) continue;
    for (const parameter of parameters) {
      const match = /^\s*q=([0-9.]+)\s*$/.exec(parameter);
      if (match?.[1] !== undefined) {
        const quality = Number.parseFloat(match[1]);
        return Number.isFinite(quality) ? quality : 1;
      }
    }
    return 1;
  }
  return 0;
}

/** SSE response headers. `X-Accel-Buffering` keeps proxies from coalescing frames. */
export const SSE_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "text/event-stream; charset=utf-8",
  "cache-control": "no-cache, no-transform",
  connection: "keep-alive",
  "x-accel-buffering": "no",
};

/**
 * Frame one JSON-RPC response as a single-message SSE stream and close.
 *
 * This is the Streamable-HTTP "server responds on the POST's own stream" shape:
 * one `message` event carrying the JSON-RPC response, then EOF. FerroGate's
 * ingress answers exactly one response per request, so there is never a second
 * frame to wait for.
 */
export function sseJsonRpcResponse(
  payload: JsonValue,
  init: { status?: number; headers?: Record<string, string>; eventId?: string } = {},
): Response {
  const event: SseEvent = { event: "message", data: JSON.stringify(payload) };
  if (init.eventId !== undefined) event.id = init.eventId;
  return sseFrameResponse([event], init);
}

/**
 * Frame SEVERAL messages onto one `text/event-stream` response and close.
 *
 * This is what a `Last-Event-ID` resume needs (#687): the frames the client
 * missed are emitted, IN THEIR ORIGINAL ORDER and carrying their ORIGINAL `id:`
 * cursors, ahead of the answer to the request that carried the cursor. Re-using
 * the original ids matters — a replayed frame given a fresh id would make the
 * client's next cursor point at a position that never existed, so a second
 * reconnect would resume from the wrong place.
 */
export function sseFrameResponse(
  events: readonly SseEvent[],
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const body = events.map((event) => encodeSseEvent(event)).join("");
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(body));
      controller.close();
    },
  });
  return new Response(stream, {
    status: init.status ?? 200,
    headers: { ...SSE_HEADERS, ...init.headers },
  });
}

// ---------------------------------------------------------------------------
// Client side: reading an upstream response
// ---------------------------------------------------------------------------

/**
 * Incrementally parse a `text/event-stream` body, returning as soon as one
 * `data:` field assembles into a complete JSON value — rather than blocking on
 * connection close, which a real SSE stream may not do promptly.
 *
 * Both the accumulated data buffer and each individual line are bounded, so a
 * peer streaming an enormous line without a newline cannot grow the buffer
 * without limit (the same DoS class as the `Content-Length` body read).
 */
export async function readSseJsonResponse(body: ReadableStream<Uint8Array>): Promise<JsonValue> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  let dataBuffer = "";
  let consumed = 0;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      consumed += value.byteLength;
      if (consumed > MAX_MCP_RESPONSE_BYTES) {
        throw new Error(`MCP SSE response exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte maximum`);
      }
      pending += decoder.decode(value, { stream: true });

      for (;;) {
        const newline = pending.indexOf("\n");
        if (newline === -1) break;
        const line = pending.slice(0, newline).replace(/\r$/, "");
        pending = pending.slice(newline + 1);

        if (line.length === 0) {
          try {
            return JSON.parse(dataBuffer) as JsonValue;
          } catch {
            dataBuffer = "";
            continue;
          }
        }
        if (line.startsWith("data:")) {
          if (dataBuffer.length > 0) dataBuffer += "\n";
          dataBuffer += line.slice("data:".length).replace(/^ /, "");
          if (dataBuffer.length > MAX_MCP_RESPONSE_BYTES) {
            throw new Error(`MCP SSE response exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte maximum`);
          }
        }
        // Other SSE fields (`event:`, `id:`, `retry:`) and `:`-prefixed
        // comment / keep-alive lines are not needed for JSON-RPC correlation.
      }
    }
    // A stream that ended without a blank line still dispatches its last event.
    if (dataBuffer.length > 0) {
      try {
        return JSON.parse(dataBuffer) as JsonValue;
      } catch {
        // fall through to the closed-stream error
      }
    }
    throw new Error("MCP SSE stream closed before a JSON-RPC response arrived");
  } finally {
    reader.releaseLock();
  }
}

/** Read a bounded JSON body, refusing anything over the cap. */
export async function readCappedJson(response: Response): Promise<JsonValue | undefined> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number.parseInt(declared, 10);
    if (Number.isFinite(length) && length > MAX_MCP_RESPONSE_BYTES) {
      throw new Error(
        `MCP JSON response Content-Length ${length} exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte maximum`,
      );
    }
  }
  const text = await response.text();
  if (text.length > MAX_MCP_RESPONSE_BYTES) {
    throw new Error(`MCP JSON response exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte maximum`);
  }
  if (text.trim().length === 0) return undefined;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return undefined;
  }
}

/** One upstream HTTP round trip. */
export interface HttpRpcResponse {
  status: number;
  json?: JsonValue;
}

/**
 * POST a JSON-RPC body to an upstream MCP endpoint over Streamable HTTP / SSE.
 * The `Accept` header advertises both shapes exactly as the Rust client does;
 * a `text/event-stream` reply is parsed incrementally.
 */
export async function postJsonRpc(
  endpoint: string,
  body: JsonValue,
  options: {
    headers?: ReadonlyArray<readonly [string, string]>;
    identity?: McpDispatchHeaders;
    transport: McpServerConfig["transport"];
    timeoutMs: number;
    fetchImpl?: typeof fetch;
  },
): Promise<HttpRpcResponse> {
  validateHttpEndpoint(endpoint);
  const headers = new Headers({
    "content-type": "application/json",
    accept:
      options.transport === "stdio" ? "application/json" : "application/json, text/event-stream",
  });
  for (const [name, value] of options.headers ?? []) headers.set(name, value);
  options.identity?.applyTo(headers);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const doFetch = options.fetchImpl ?? fetch;
    const response = await doFetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
    if (response.ok && contentType.includes("text/event-stream") && response.body !== null) {
      return { status: response.status, json: await readSseJsonResponse(response.body) };
    }
    const json = await readCappedJson(response);
    return json === undefined ? { status: response.status } : { status: response.status, json };
  } finally {
    clearTimeout(timer);
  }
}

/** Network transports require an http/https URL. Port of `validate_http_endpoint`. */
export function validateHttpEndpoint(raw: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`invalid MCP endpoint ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("MCP network transports require http or https url");
  }
}

/**
 * Streamable-HTTP routing headers mirrored onto an outbound modern request.
 * Only emitted for the modern era on the Streamable-HTTP transport, matching
 * `HttpMcpClient::routing_headers`.
 */
export function outboundRoutingHeaders(
  method: string,
  name: string | undefined,
  options: { modern: boolean; transport: McpServerConfig["transport"] },
): Array<[string, string]> {
  if (!options.modern || options.transport !== "streamable_http") return [];
  const headers: Array<[string, string]> = [
    [MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION],
    [MCP_METHOD_HEADER, method],
  ];
  if (name !== undefined) headers.push([MCP_NAME_HEADER, encodeMcpHeaderValue(name)]);
  return headers;
}

// ---------------------------------------------------------------------------
// The HTTP MCP host
// ---------------------------------------------------------------------------

interface UpstreamSession {
  config: McpServerConfig;
  negotiation?: McpNegotiatedProtocol;
  tools: McpTool[];
  nextId: number;
}

/**
 * A `fetch`-based MCP host over Streamable HTTP / SSE upstreams. Owns protocol
 * negotiation (modern `server/discover`, else the legacy `initialize`
 * handshake), the deny-by-default `toolsToExecute` allowlist, and the
 * `{server}-{remote}` namespacing with longest-prefix resolution.
 *
 * ## Session state — the `McpManager` port (marker CLOSED)
 *
 * Rust's `McpManager` holds a process-wide `HashMap<name, McpSession>` plus a
 * `health_check_and_reconnect()` loop. A Worker has no process, and this class
 * used to carry the map per ISOLATE, which was recorded as
 * `PORT_TODO(inventory-edge-control §MCP "session manager")` — explicitly not a
 * platform limit.
 *
 * That marker is now closed by `src/session.ts`: pass a
 * {@link McpSessionStorePort} and the negotiated protocol, the discovered tool
 * list and the connection health live in ONE `FerroGateMcpSession` Durable
 * Object per `(tenant, server)`, so every isolate serving a tenant reads the
 * same session and an upstream outage is recorded once globally rather than
 * once per isolate. {@link HttpMcpUpstreams.healthCheckAndReconnect} is the
 * port of the Rust loop, and {@link HttpMcpUpstreams.statuses} of
 * `McpManager::statuses`.
 *
 * The per-isolate map is KEPT as the request-local cache in front of the DO (a
 * DO round trip per `tools/list` would be a regression, not a port) and as the
 * whole implementation when NO store is supplied — a deployment without the
 * `MCP_SESSION` binding degrades to exactly the previous behaviour instead of
 * failing. What that degraded mode costs is unchanged and still true: more
 * `server/discover` / `initialize` round trips, and no cross-isolate health
 * signal.
 */
export class HttpMcpUpstreams implements McpUpstreamPort {
  readonly #sessions = new Map<string, UpstreamSession>();
  readonly #fetch: typeof fetch;
  readonly #store: McpSessionStorePort | undefined;
  readonly #policy: McpReconnectPolicy;
  readonly #now: () => number;

  constructor(
    configs: readonly McpServerConfig[],
    fetchImpl?: typeof fetch,
    options: {
      /** The shared session manager. Absent ⇒ per-isolate sessions only. */
      readonly sessions?: McpSessionStorePort;
      readonly policy?: McpReconnectPolicy;
      /** Unix SECONDS, injectable so `lastConnectedAtUnix` is assertable. */
      readonly nowUnix?: () => number;
    } = {},
  ) {
    this.#fetch = fetchImpl ?? fetch;
    this.#store = options.sessions;
    this.#policy = options.policy ?? DEFAULT_RECONNECT_POLICY;
    this.#now = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
    for (const config of configs) {
      this.#sessions.set(config.name, { config, tools: [], nextId: 1 });
    }
  }

  /**
   * Rust `McpManager::statuses` — one row per configured upstream.
   *
   * Read from the SHARED store when one is bound, so an operator surface sees
   * the fleet's view of an upstream rather than the isolate that happened to
   * answer. Without a store the answer is this isolate's own view, which is
   * exactly what it was before the session manager existed.
   */
  async statuses(): Promise<readonly McpServerStatus[]> {
    const rows: McpServerStatus[] = [];
    for (const session of this.#sessions.values()) {
      rows.push(statusOf(session.config.name, await this.#state(session)));
    }
    return rows;
  }

  /**
   * Rust `McpManager::health_check_and_reconnect`, driven by the caller (a
   * `scheduled` handler or an operator route) rather than by a background
   * thread — a Worker has none.
   *
   * Per session, faithfully: probe only a session the shared record says is
   * CONNECTED; on a failed probe record `MCP health check failed` and fall
   * through to reconnect; then attempt to re-negotiate up to
   * `maxReconnectAttempts` times, stopping at the first success. A `stdio`
   * upstream is skipped — it can never connect here at all.
   */
  async healthCheckAndReconnect(): Promise<readonly McpServerStatus[]> {
    for (const session of this.#sessions.values()) {
      if (session.config.transport === "stdio") continue;
      const state = await this.#state(session);
      if (state.connected && state.negotiation !== undefined) {
        // Adopt the shared negotiation so the probe speaks the version the
        // session actually negotiated, not a freshly guessed one.
        session.negotiation = state.negotiation;
        if (await this.#probe(session, state.negotiation)) continue;
        session.negotiation = undefined;
        session.tools = [];
        await this.#store?.unhealthy(session.config.name);
      }
      for (let attempt = 0; attempt < this.#policy.maxReconnectAttempts; attempt += 1) {
        session.negotiation = undefined;
        session.tools = [];
        try {
          await this.#negotiate(session, true);
          break;
        } catch {
          // `#negotiate` already recorded the failure (and the doubled
          // backoff) on the shared record; keep trying up to the bound.
        }
      }
    }
    return await this.statuses();
  }

  /** The shared record when a store is bound, else this isolate's view. */
  async #state(session: UpstreamSession): Promise<McpSessionState> {
    if (this.#store !== undefined) return await this.#store.read(session.config.name);
    const local: McpSessionState = {
      connected: session.negotiation !== undefined,
      tools: session.tools,
      reconnectAttempts: 0,
      nextReconnectBackoffSecs: this.#policy.minReconnectBackoffSecs,
    };
    if (session.negotiation !== undefined) local.negotiation = session.negotiation;
    return local;
  }

  /**
   * Rust `HttpMcpClient::health_check`: modern sessions re-run
   * `server/discover` and require the negotiated version to still be
   * advertised; legacy sessions send `ping` and require no JSON-RPC error.
   */
  async #probe(session: UpstreamSession, negotiation: McpNegotiatedProtocol): Promise<boolean> {
    try {
      if (negotiation.mode === "modern") {
        const response = await this.#post(
          session,
          "server/discover",
          undefined,
          modernDiscoverParams(),
          McpDispatchHeaders.empty(),
          true,
        );
        if (response.status < 200 || response.status >= 300) return false;
        return response.json !== undefined && discoverSupportsCurrentVersion(response.json);
      }
      const response = await this.#post(
        session,
        "ping",
        undefined,
        {},
        McpDispatchHeaders.empty(),
        false,
      );
      if (response.status < 200 || response.status >= 300) return false;
      return response.json !== undefined && jsonRpcErrorCode(response.json) === undefined;
    } catch {
      return false;
    }
  }

  listServers(): readonly McpServerConfig[] {
    return [...this.#sessions.values()].map((session) => session.config);
  }

  getServer(name: string): McpServerConfig | undefined {
    return this.#sessions.get(name)?.config;
  }

  /**
   * The multiplexed fan-in (#687).
   *
   * A single unreachable upstream must not blank the whole catalogue — the Rust
   * manager keeps the other sessions' tools listed too — but it must not vanish
   * either. Every failure is CAUGHT and RECORDED, so the caller can be told the
   * union is incomplete instead of reading a shorter list as "that tool does
   * not exist".
   */
  async fanIn(): Promise<McpFanIn> {
    const tools: McpTool[] = [];
    const degraded: McpUpstreamFailure[] = [];
    for (const session of this.#sessions.values()) {
      try {
        tools.push(...(await this.#sessionTools(session)));
      } catch (cause) {
        degraded.push({
          server: session.config.name,
          code:
            cause instanceof McpExecutionError ? cause.code : ("mcp_server_unavailable" as const),
          message: cause instanceof Error ? cause.message : String(cause),
        });
      }
    }
    return { tools, degraded };
  }

  async listTools(): Promise<readonly McpTool[]> {
    return (await this.fanIn()).tools;
  }

  /**
   * Resolve a flat `{server}-{remote}` name against the CATALOGUE (#687).
   *
   * The prefix scan only decides which upstreams are worth interrogating (so a
   * `tools/call` does not hand-shake the whole fleet); it deliberately keeps
   * EVERY prefix match rather than the longest, because the longest-prefix rule
   * is what silently shadowed one of two colliding tools.
   *
   * An upstream that fails to list is skipped rather than propagated: it cannot
   * claim the name, and letting its outage turn a resolvable call into an
   * ambiguity — or into a hard failure — would let one dead server break a tool
   * on a healthy one. The caller still learns about it through {@link fanIn}.
   */
  async resolveTool(name: string, selector?: string | undefined): Promise<McpToolResolution> {
    const candidates = candidateServerNames(this.#sessions.keys(), name).filter(
      (candidate) => selector === undefined || candidate.serverName === selector,
    );
    const claimants: McpTool[] = [];
    for (const candidate of candidates) {
      const session = this.#sessions.get(candidate.serverName);
      if (session === undefined) continue;
      let tools: McpTool[];
      try {
        tools = await this.#sessionTools(session);
      } catch {
        continue;
      }
      claimants.push(...tools.filter((tool) => tool.name === name));
    }
    return resolveAcrossCatalog(claimants, name, selector);
  }

  async callTool(
    tool: McpTool,
    args: JsonValue,
    identity: McpDispatchHeaders,
    _context: DispatchContext,
  ): Promise<McpToolExecutionResult> {
    const session = this.#sessions.get(tool.serverName);
    if (session === undefined) {
      throw new McpExecutionError(
        "tool_not_found",
        `MCP tool ${tool.name} did not match any configured MCP server`,
      );
    }
    if (session.config.transport === "stdio") {
      // PORT-TODO(L: inventory-edge-control §MCP): stdio transport requires Containers.
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${session.config.name} uses the stdio transport, which Workers cannot host (no process spawn)`,
      );
    }
    if (!toolPermitted(session.config, tool.remoteName)) {
      throw new McpExecutionError(
        "tool_denied",
        `MCP tool ${session.config.name}-${tool.remoteName} is not allowlisted for execution`,
      );
    }
    const negotiation = await this.#negotiate(session);
    const modern = negotiation.mode === "modern";
    const params = callToolParams(tool.remoteName, args);
    const response = await this.#post(
      session,
      "tools/call",
      tool.remoteName,
      modern ? modernRequestParams(params) : params,
      identity,
    );
    if (response.status === 401) {
      throw new McpExecutionError(
        "mcp_upstream_unauthorized",
        `MCP server ${session.config.name} rejected the dispatched identity`,
      );
    }
    if (response.json === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${session.config.name} returned HTTP ${response.status} with no JSON-RPC body`,
      );
    }
    try {
      return parseCallResult(response.json);
    } catch (cause) {
      throw new McpExecutionError(
        "tool_execution_failed",
        cause instanceof Error ? cause.message : String(cause),
      );
    }
  }

  /**
   * The exclude half of the multiplex filter pair (#687), applied on EVERY
   * read of a tool list.
   *
   * `session.tools` is a cache — the isolate's own, and (through `#negotiate`)
   * the shared `MCP_SESSION` Durable Object's. Filtering only where the list is
   * DISCOVERED would leave every warm session serving an excluded tool until
   * its next reconnect, which for a deny rule is a security window rather than
   * a staleness nuisance. So the filter runs on the way OUT, not on the way in.
   */
  #permitted(session: UpstreamSession, tools: readonly McpTool[]): McpTool[] {
    return tools.filter((tool) => toolPermitted(session.config, tool.remoteName));
  }

  async #sessionTools(session: UpstreamSession): Promise<McpTool[]> {
    if (session.tools.length > 0) return this.#permitted(session, session.tools);
    if (session.config.transport === "stdio") return [];
    const negotiation = await this.#negotiate(session);
    // `#negotiate` may have ADOPTED the shared session's tool list, which is
    // the whole point of the manager: a warm upstream costs a cold isolate one
    // DO read instead of a handshake plus a `tools/list`.
    if (session.tools.length > 0) return this.#permitted(session, session.tools);
    const params = negotiation.mode === "modern" ? modernRequestParams({}) : {};
    const response = await this.#post(
      session,
      "tools/list",
      undefined,
      params,
      McpDispatchHeaders.empty(),
    );
    if (response.json === undefined) {
      const detail = `MCP server ${session.config.name} returned HTTP ${response.status} for tools/list`;
      await this.#store?.failed(session.config.name, detail);
      session.negotiation = undefined;
      throw new McpExecutionError("mcp_server_unavailable", detail);
    }
    const parsed: ParsedToolDef[] = parseToolsList(response.json);
    session.tools = parsed
      .filter((tool) => toolPermitted(session.config, tool.name))
      .map((tool) => {
        const entry: McpTool = {
          name: namespacedToolName(session.config.name, tool.name),
          serverName: session.config.name,
          remoteName: tool.name,
          inputSchema: tool.input_schema,
          autoExecute: toolAllowlisted(session.config.toolsToAutoExecute, tool.name),
        };
        if (tool.description !== undefined) entry.description = tool.description;
        return entry;
      });
    // Publish the discovered catalog so the NEXT isolate does not re-discover
    // it. Rust's manager held the same list on the shared session.
    if (session.negotiation !== undefined) {
      await this.#store?.connected(
        session.config.name,
        session.negotiation,
        session.tools,
        this.#now(),
      );
    }
    return this.#permitted(session, session.tools);
  }

  /**
   * Resolve the negotiated protocol, preferring the SHARED session.
   *
   * Order — isolate cache, then the shared record, then a real handshake:
   * cheapest first, and the handshake's outcome (either arm) is written back
   * so the next isolate inherits it. `force` re-handshakes unconditionally and
   * is what {@link healthCheckAndReconnect}'s reconnect loop uses.
   */
  async #negotiate(session: UpstreamSession, force = false): Promise<McpNegotiatedProtocol> {
    if (!force && session.negotiation !== undefined) return session.negotiation;
    if (!force && this.#store !== undefined) {
      const shared = await this.#store.read(session.config.name);
      if (shared.connected && shared.negotiation !== undefined) {
        session.negotiation = shared.negotiation;
        if (session.tools.length === 0 && shared.tools.length > 0) session.tools = shared.tools;
        return shared.negotiation;
      }
    }
    let negotiated: McpNegotiatedProtocol;
    try {
      negotiated = await this.#handshake(session);
    } catch (cause) {
      // Record the failure on the SHARED session — this is what makes an
      // upstream outage a fleet-wide fact instead of a per-isolate one, and it
      // is what advances `reconnectAttempts` / the doubled backoff.
      session.negotiation = undefined;
      session.tools = [];
      await this.#store?.failed(
        session.config.name,
        cause instanceof Error ? cause.message : String(cause),
      );
      throw cause;
    }
    session.negotiation = negotiated;
    await this.#store?.connected(session.config.name, negotiated, session.tools, this.#now());
    return negotiated;
  }

  /** The wire handshake itself — Rust `McpSession::connect`. */
  async #handshake(session: UpstreamSession): Promise<McpNegotiatedProtocol> {
    if (session.config.transport !== "streamable_http") {
      return await this.#initializeLegacy(session, undefined);
    }
    const response = await this.#post(
      session,
      "server/discover",
      undefined,
      modernDiscoverParams(),
      McpDispatchHeaders.empty(),
      true,
    );
    if (response.status >= 200 && response.status < 300) {
      if (response.json !== undefined && jsonRpcErrorCode(response.json) !== undefined) {
        throw new McpExecutionError(
          "mcp_server_unavailable",
          `MCP modern discovery returned JSON-RPC error code ${jsonRpcErrorCode(response.json)}`,
        );
      }
      if (response.json === undefined || !discoverSupportsCurrentVersion(response.json)) {
        throw new McpExecutionError(
          "mcp_server_unavailable",
          "MCP modern discovery did not advertise the requested protocol version",
        );
      }
      return { mode: "modern", version: MCP_PROTOCOL_VERSION };
    }
    if (response.status === 401) {
      throw new McpExecutionError(
        "mcp_upstream_unauthorized",
        `MCP server ${session.config.name} rejected discovery`,
      );
    }
    const reason = httpLegacyDowngradeReason(response.status, response.json);
    if (reason !== undefined) {
      return await this.#initializeLegacy(session, reason);
    }
    throw new McpExecutionError(
      "mcp_server_unavailable",
      `MCP modern discovery returned HTTP ${response.status}`,
    );
  }

  async #initializeLegacy(
    session: UpstreamSession,
    downgradeReason: McpNegotiatedProtocol["downgradeReason"],
  ): Promise<McpNegotiatedProtocol> {
    const response = await this.#post(
      session,
      "initialize",
      undefined,
      {
        protocolVersion: MCP_LEGACY_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { ...FERROGATE_CLIENT_INFO },
      },
      McpDispatchHeaders.empty(),
      false,
    );
    const result =
      response.json !== null &&
      typeof response.json === "object" &&
      !Array.isArray(response.json) &&
      typeof response.json["result"] === "object" &&
      response.json["result"] !== null &&
      !Array.isArray(response.json["result"])
        ? (response.json["result"] as Record<string, JsonValue>)
        : undefined;
    const raw = result?.["protocolVersion"];
    const version = resolveLegacyProtocolVersion(typeof raw === "string" ? raw : undefined);
    if (version === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        "MCP initialize returned an invalid legacy protocol version",
      );
    }
    const negotiated: McpNegotiatedProtocol = { mode: "legacy", version };
    if (downgradeReason !== undefined) negotiated.downgradeReason = downgradeReason;
    return negotiated;
  }

  async #post(
    session: UpstreamSession,
    method: string,
    name: string | undefined,
    params: JsonValue,
    identity: McpDispatchHeaders,
    modernOverride?: boolean,
  ): Promise<HttpRpcResponse> {
    const endpoint = session.config.url;
    if (endpoint === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${session.config.name} requires url`,
      );
    }
    const modern = modernOverride ?? session.negotiation?.mode === "modern";
    const id = session.nextId;
    session.nextId += 1;
    const headers: Array<[string, string]> = Object.entries(session.config.headers ?? {});
    headers.push(
      ...outboundRoutingHeaders(method, name, { modern, transport: session.config.transport }),
    );
    return postJsonRpc(
      endpoint,
      { jsonrpc: "2.0", id, method, params },
      {
        headers,
        identity,
        transport: session.config.transport,
        timeoutMs: session.config.timeoutMs,
        fetchImpl: this.#fetch,
      },
    );
  }
}
