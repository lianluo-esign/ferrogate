/**
 * MCP transports: Streamable HTTP and SSE, in both directions.
 *
 * Clean-room port of `crates/ferrogate-mcp/src/http_client.rs` (the outbound
 * host client, its 16 MiB response cap, and the incremental `data:` SSE parse
 * that returns on the FIRST complete JSON value rather than blocking on
 * connection close) plus the server side of the Streamable-HTTP contract the
 * FerroGate ingress speaks.
 *
 * PORT-TODO(inventory-edge-control §MCP): stdio transport requires Containers.
 * Workers cannot spawn processes, so `McpTransport::Stdio` upstreams have no
 * outbound implementation here; {@link HttpMcpUpstreams} refuses them at
 * dispatch with `mcp_server_unavailable` instead of silently treating them as
 * HTTP.
 *
 * PORT-TODO(inventory-edge-control §MCP): the modern FerroGate ingress is
 * deliberately STATELESS (`mcp_ingress.rs`), so no `Mcp-Session-Id` is minted
 * and no resumable `Last-Event-ID` replay log is kept. A resumable server-side
 * stream needs a Durable Object per session (the `McpAgent` pattern).
 */
import type { JsonValue } from "@ferrogate/core";

import {
  callToolParams,
  parseCallResult,
  parseToolsList,
  type McpToolExecutionResult,
  type ParsedToolDef,
} from "./jsonrpc.js";
import {
  discoverSupportsCurrentVersion,
  encodeMcpHeaderValue,
  httpLegacyDowngradeReason,
  jsonRpcErrorCode,
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_HEADER,
  MCP_LEGACY_PROTOCOL_VERSION,
  modernDiscoverParams,
  modernRequestParams,
  resolveLegacyProtocolVersion,
  FERROGATE_CLIENT_INFO,
  type McpNegotiatedProtocol,
} from "./protocol.js";
import {
  McpDispatchHeaders,
  McpExecutionError,
  resolveNamespacedTool,
  toolAllowlisted,
  type DispatchContext,
  type McpServerConfig,
  type McpTool,
  type McpUpstreamPort,
} from "./ports.js";

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
  const frame = encodeSseEvent(event);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(frame));
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
 * Session state is per-isolate. PORT-TODO(inventory-edge-control §MCP): a
 * long-lived, shared session (the Rust `McpManager`'s `HashMap<name,
 * McpSession>` with health-check/reconnect) belongs in a Durable Object — one
 * DO per MCP session, mirroring the `McpAgent` pattern.
 */
export class HttpMcpUpstreams implements McpUpstreamPort {
  readonly #sessions = new Map<string, UpstreamSession>();
  readonly #fetch: typeof fetch;

  constructor(configs: readonly McpServerConfig[], fetchImpl?: typeof fetch) {
    this.#fetch = fetchImpl ?? fetch;
    for (const config of configs) {
      this.#sessions.set(config.name, { config, tools: [], nextId: 1 });
    }
  }

  listServers(): readonly McpServerConfig[] {
    return [...this.#sessions.values()].map((session) => session.config);
  }

  getServer(name: string): McpServerConfig | undefined {
    return this.#sessions.get(name)?.config;
  }

  async listTools(): Promise<readonly McpTool[]> {
    const listed: McpTool[] = [];
    for (const session of this.#sessions.values()) {
      try {
        listed.push(...(await this.#sessionTools(session)));
      } catch {
        // A single unreachable upstream must not blank the whole catalog; the
        // Rust manager keeps the other sessions' tools listed too.
      }
    }
    return listed;
  }

  async toolByName(name: string): Promise<McpTool | undefined> {
    const resolved = resolveNamespacedTool([...this.#sessions.keys()], name);
    if (resolved === undefined) return undefined;
    const session = this.#sessions.get(resolved.serverName);
    if (session === undefined) return undefined;
    const tools = await this.#sessionTools(session);
    return tools.find((tool) => tool.name === name);
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
      // PORT-TODO(inventory-edge-control §MCP): stdio transport requires Containers.
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${session.config.name} uses the stdio transport, which Workers cannot host (no process spawn)`,
      );
    }
    if (!toolAllowlisted(session.config.toolsToExecute, tool.remoteName)) {
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

  async #sessionTools(session: UpstreamSession): Promise<McpTool[]> {
    if (session.tools.length > 0) return session.tools;
    if (session.config.transport === "stdio") return [];
    const negotiation = await this.#negotiate(session);
    const params = negotiation.mode === "modern" ? modernRequestParams({}) : {};
    const response = await this.#post(
      session,
      "tools/list",
      undefined,
      params,
      McpDispatchHeaders.empty(),
    );
    if (response.json === undefined) {
      throw new McpExecutionError(
        "mcp_server_unavailable",
        `MCP server ${session.config.name} returned HTTP ${response.status} for tools/list`,
      );
    }
    const parsed: ParsedToolDef[] = parseToolsList(response.json);
    session.tools = parsed
      .filter((tool) => toolAllowlisted(session.config.toolsToExecute, tool.name))
      .map((tool) => {
        const entry: McpTool = {
          name: `${session.config.name}-${tool.name}`,
          serverName: session.config.name,
          remoteName: tool.name,
          inputSchema: tool.input_schema,
          autoExecute: toolAllowlisted(session.config.toolsToAutoExecute, tool.name),
        };
        if (tool.description !== undefined) entry.description = tool.description;
        return entry;
      });
    return session.tools;
  }

  async #negotiate(session: UpstreamSession): Promise<McpNegotiatedProtocol> {
    if (session.negotiation !== undefined) return session.negotiation;
    if (session.config.transport !== "streamable_http") {
      session.negotiation = await this.#initializeLegacy(session, undefined);
      return session.negotiation;
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
      session.negotiation = { mode: "modern", version: MCP_PROTOCOL_VERSION };
      return session.negotiation;
    }
    if (response.status === 401) {
      throw new McpExecutionError(
        "mcp_upstream_unauthorized",
        `MCP server ${session.config.name} rejected discovery`,
      );
    }
    const reason = httpLegacyDowngradeReason(response.status, response.json);
    if (reason !== undefined) {
      session.negotiation = await this.#initializeLegacy(session, reason);
      return session.negotiation;
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
