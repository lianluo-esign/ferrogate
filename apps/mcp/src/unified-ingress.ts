/**
 * The composition seam that puts the unified client session (#687 legs 2 and 3)
 * on the request path.
 *
 * It sits in the same place, and for the same reason, as `./upstreams.ts`:
 * `resolvePorts` is synchronous and runs BEFORE authentication, but a client
 * session is addressed by `(tenant, session id)` and the tenant is not known
 * until a caller has been authenticated. So the session is resolved AFTER
 * authentication, from `./routes/ingress.ts`, against the host
 * `withTenantUpstreams` already narrowed to that tenant's catalogue.
 *
 * That ordering is load-bearing rather than incidental: the upstream set a
 * session binds is read off the TENANT'S host, so a session can never name an
 * upstream the tenant is not entitled to see. The fence is the same one the
 * catalogue has, inherited rather than re-implemented.
 *
 * ## The refusal ladder
 *
 * | condition | answer |
 * |---|---|
 * | no `Mcp-Session-Id`, method is `initialize` | mint one |
 * | no `Mcp-Session-Id`, any other method | no session — the stateless behaviour this ingress always had |
 * | `Mcp-Session-Id` naming a session this tenant never opened | `404 mcp_session_not_found` |
 * | `Mcp-Session-Id` naming a session EVICTED for idleness (#765) | `404 mcp_session_not_found`, message naming the eviction |
 * | ...with a `Last-Event-ID` as well | `400 mcp_session_not_resumable`, message naming the eviction |
 * | `Last-Event-ID` with no live session | `400 mcp_session_not_resumable` |
 * | `Last-Event-ID` on a non-SSE request | `400 mcp_session_not_resumable` |
 * | `Last-Event-ID` the log cannot honour exactly | `400 mcp_session_not_resumable` |
 *
 * Every one of those is a REFUSAL rather than a silent downgrade, and the
 * reason is the same in each case: a client that thinks it resumed and did not
 * will never ask for the missing history again.
 */
import type { JsonValue } from "@ferrogate/core";

import type { JsonRpcResponse } from "./jsonrpc.js";
import {
  type AuthContext,
  type McpEnv,
  type McpPorts,
  type UpstreamAttributionSink,
  isJsonObjectValue,
} from "./ports.js";
import {
  LAST_EVENT_ID_HEADER,
  MCP_SESSION_ID_HEADER,
  UNIFIED_ADDED_META,
  UNIFIED_DROPPED_META,
  UNIFIED_REMOVED_META,
  UNIFIED_SESSION_META,
  type UnifiedFrame,
  type UnifiedReconcile,
  UnifiedSessionStore,
  evictionReason,
  mintSessionId,
  parseUnifiedCursor,
  unifiedCursorToken,
} from "./unified.js";

/** Error codes this seam answers with, so the ingress never spells them twice. */
export const SESSION_NOT_FOUND = "mcp_session_not_found";
export const SESSION_NOT_RESUMABLE = "mcp_session_not_resumable";

/** A live client session for one request. */
export interface UnifiedSessionBinding {
  readonly sessionId: string;
  readonly store: UnifiedSessionStore;
  /** `true` when this request is the one that opened it. */
  readonly minted: boolean;
  /** The catalogue delta observed on this request, if any. */
  readonly reconcile: UnifiedReconcile | undefined;
  /** Frames the client missed, to be emitted BEFORE this request's answer. */
  readonly replay: readonly UnifiedFrame[];
}

export type UnifiedSessionResolution =
  | { readonly ok: true; readonly binding: UnifiedSessionBinding | undefined }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

/**
 * Whether this deployment offers unified sessions at all.
 *
 * Absent binding ⇒ the ingress behaves exactly as it did before this slice: no
 * session is minted and the response carries no session header. What it does
 * NOT do is accept a session id or a resume cursor it cannot honour — see
 * {@link resolveUnifiedSession}. Degrading to "no sessions" is visible to a
 * client; degrading to "I accepted your cursor and ignored it" is not.
 */
export function unifiedSessionsBound(env: McpEnv): boolean {
  return env.MCP_CLIENT_SESSION !== undefined;
}

/** The tenant a client session is addressed under. Same rule as the catalogue. */
export function sessionTenant(auth: AuthContext): string | undefined {
  return auth.organizationId;
}

/**
 * Resolve (or mint) the client session for one authenticated request.
 *
 * `servers` is read from the TENANT'S already-narrowed host, which is what
 * makes a session's upstream set structurally per-tenant.
 */
export async function resolveUnifiedSession(
  env: McpEnv,
  headers: Headers,
  ports: McpPorts,
  auth: AuthContext,
  method: string,
  options: { readonly wantsStream: boolean; readonly nowUnix?: () => number } = {
    wantsStream: false,
  },
): Promise<UnifiedSessionResolution> {
  const requested = headers.get(MCP_SESSION_ID_HEADER)?.trim();
  const cursorRaw = headers.get(LAST_EVENT_ID_HEADER)?.trim();
  const hasSessionHeader = requested !== undefined && requested !== "";
  const hasCursor = cursorRaw !== undefined && cursorRaw !== "";

  const tenantId = sessionTenant(auth);
  if (!unifiedSessionsBound(env) || tenantId === undefined || tenantId === "") {
    // Nothing here can be honoured, so nothing here is accepted.
    if (hasSessionHeader) {
      return {
        ok: false,
        status: 404,
        code: SESSION_NOT_FOUND,
        message: `no MCP session ${requested} is open for this credential`,
      };
    }
    if (hasCursor) {
      return {
        ok: false,
        status: 400,
        code: SESSION_NOT_RESUMABLE,
        message: "Last-Event-ID requires an open MCP session; send Mcp-Session-Id",
      };
    }
    return { ok: true, binding: undefined };
  }

  const store = new UnifiedSessionStore(
    env.MCP_CLIENT_SESSION as NonNullable<McpEnv["MCP_CLIENT_SESSION"]>,
    tenantId,
  );
  const servers = ports.upstreams.listServers().map((config) => config.name);

  let sessionId: string;
  let minted = false;
  let reconcile: UnifiedReconcile | undefined;
  if (hasSessionHeader) {
    sessionId = requested as string;
    // The cross-tenant fence: this store can only address objects named
    // `(this tenant, id)`, so another tenant's id resolves to an object that
    // was never opened and is UNKNOWN here rather than forbidden.
    const status = await store.status(sessionId);
    if (status.kind === "evicted") {
      // #765. An evicted session is NOT the same answer as an unknown one, and
      // the difference is the whole point of keeping a tombstone: this client
      // had a real session and it was taken away by an operator policy, so it
      // is told which policy and when. Everything else in this ladder would
      // answer "no such session", which is true and useless.
      const message = evictionReason(status.tombstone);
      // With a cursor this is a RESUME refusal — the same code and shape as
      // #687's three others, because the client's question was "continue this
      // stream" and the honest answer is "that stream no longer exists".
      // Without one the question was only "is my session open", which the
      // 404 row already answers; only the message changes.
      if (hasCursor) {
        return { ok: false, status: 400, code: SESSION_NOT_RESUMABLE, message };
      }
      return { ok: false, status: 404, code: SESSION_NOT_FOUND, message };
    }
    if (status.kind === "unknown") {
      return {
        ok: false,
        status: 404,
        code: SESSION_NOT_FOUND,
        message: `no MCP session ${sessionId} is open for this credential`,
      };
    }
    reconcile = await store.reconcile(sessionId, servers);
  } else if (method === "initialize") {
    sessionId = mintSessionId();
    minted = true;
    const now = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
    await store.open(sessionId, servers, now());
  } else {
    if (hasCursor) {
      return {
        ok: false,
        status: 400,
        code: SESSION_NOT_RESUMABLE,
        message: "Last-Event-ID requires an open MCP session; send Mcp-Session-Id",
      };
    }
    return { ok: true, binding: undefined };
  }

  let replay: readonly UnifiedFrame[] = [];
  if (hasCursor) {
    const refuse = (message: string): UnifiedSessionResolution => ({
      ok: false,
      status: 400,
      code: SESSION_NOT_RESUMABLE,
      message,
    });
    if (!options.wantsStream) {
      return refuse(
        "resuming a stream requires Accept: text/event-stream; a JSON response cannot carry the replayed frames",
      );
    }
    const cursor = parseUnifiedCursor(cursorRaw as string);
    if (cursor === undefined) {
      return refuse(`Last-Event-ID ${cursorRaw} is not a FerroGate MCP resume cursor`);
    }
    if (cursor.sessionId !== sessionId) {
      // Honouring it would replay THIS session's frames at a position that
      // means something only in another one — the exact "resumed from the wrong
      // point" failure this contract exists to prevent.
      return refuse(
        `Last-Event-ID names session ${cursor.sessionId}, which is not the session on this request`,
      );
    }
    const answer = await store.replay(sessionId, cursor.seq);
    if (answer.kind === "refused") return refuse(answer.reason);
    replay = answer.frames;
  }

  return { ok: true, binding: { sessionId, store, minted, reconcile, replay } };
}

/**
 * A sink that collects which upstreams contributed to one response.
 *
 * It is handed to the chokepoint through `DispatchContext`, so the attribution
 * comes from the code that actually resolved the upstream rather than from a
 * second guess at the ingress — the same reasoning that made `#677/#678`'s
 * audit attribution read the catalogue entry instead of splitting the name.
 */
export function attributionSink(): UpstreamAttributionSink & {
  readonly servers: string[];
  readonly failures: Array<{ server: string; message: string }>;
} {
  const servers: string[] = [];
  const failures: Array<{ server: string; message: string }> = [];
  return {
    servers,
    failures,
    note(server: string): void {
      if (!servers.includes(server)) servers.push(server);
    },
    noteFailure(server: string, message: string): void {
      if (!failures.some((failure) => failure.server === server))
        failures.push({ server, message });
    },
  };
}

/**
 * Stamp the session facts onto a JSON-RPC result's `_meta`.
 *
 * `_meta` is the MCP-sanctioned place for implementation-defined metadata, and
 * the multiplex contract already uses it for the per-tool selector and the
 * degraded-upstream report, so this is one vocabulary rather than two.
 *
 * A response that is an ERROR, or whose result is not an object, is left
 * untouched: there is no sanctioned place to put this on either, and
 * fabricating one would change a shape a client parses.
 */
export function stampSessionMeta(
  response: JsonRpcResponse | undefined,
  facts: {
    readonly sessionId: string;
    /** Present only on the request that OPENED the session. */
    readonly openedWith?: readonly string[];
    readonly added: readonly string[];
    readonly removed: readonly string[];
    readonly dropped: readonly string[];
  },
): void {
  if (response === undefined || !isJsonObjectValue(response.result)) return;
  const result = response.result as Record<string, JsonValue>;
  const meta = isJsonObjectValue(result["_meta"])
    ? (result["_meta"] as Record<string, JsonValue>)
    : {};
  if (facts.openedWith !== undefined) {
    meta[UNIFIED_SESSION_META] = { id: facts.sessionId, upstreams: [...facts.openedWith] };
  }
  if (facts.added.length > 0) meta[UNIFIED_ADDED_META] = [...facts.added];
  if (facts.removed.length > 0) meta[UNIFIED_REMOVED_META] = [...facts.removed];
  if (facts.dropped.length > 0) meta[UNIFIED_DROPPED_META] = [...facts.dropped];
  if (Object.keys(meta).length > 0) result["_meta"] = meta;
}

/** The SSE `id:` cursor for one appended frame. */
export function frameCursor(binding: UnifiedSessionBinding, seq: number): string {
  return unifiedCursorToken(binding.sessionId, seq);
}
