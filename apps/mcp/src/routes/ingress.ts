/**
 * The two MCP ingress operations: the JSON-RPC endpoint and the REST transport
 * for the same governed tool chokepoint.
 *
 * | operation_id     | route                       | auth                   |
 * |------------------|-----------------------------|------------------------|
 * | `mcpJsonRpc`     | `POST /v1/mcp`              | method_dependent scope |
 * | `executeMcpTool` | `POST /v1/mcp/tool/execute` | bearer, MCP execute    |
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/mcp_rpc.rs` and
 * `server/mcp_ingress.rs` (`docs/legacy/inventory-edge-control.md` §4).
 *
 * Lifted out of `src/index.ts` so the composition root has a module to mount
 * rather than an inline route — the same shape `apps/gateway` uses, and the
 * shape the anti-drift gate cross-checks.
 */
import { dispatchMcpRequest, planIngress } from "../dispatch.js";
import { type DrainBindings, isDrainGuardedRpcMethod } from "../drain.js";
import {
  authenticateRequest,
  errorEnvelope,
  readCappedBody,
  requestIdentity,
  respondError,
} from "../http.js";
import {
  JsonRpcErrorCode,
  type JsonRpcResponse,
  jsonRpcError,
  renderJsonRpcResponse,
} from "../jsonrpc.js";
import { type McpPorts, resolvePorts } from "../ports.js";
import { type ToolExecutionRequest, executeToolWithGovernance, isBuiltinTool } from "../tools.js";
import { type SseEvent, prefersEventStream, sseFrameResponse } from "../transport.js";
import {
  type UnifiedSessionBinding,
  attributionSink,
  frameCursor,
  resolveUnifiedSession,
  stampSessionMeta,
} from "../unified-ingress.js";
import { MCP_SESSION_ID_HEADER } from "../unified.js";
import { withTenantUpstreams } from "../upstreams.js";
import { type McpRouter, type RouteModule, methodNotAllowed } from "./index.js";

/** Contract operations this module mounts. */
export const INGRESS_OPERATION_IDS = ["mcpJsonRpc", "executeMcpTool"] as const;

export function ingressRouteModule(): RouteModule {
  return {
    name: "ingress",
    operationIds: INGRESS_OPERATION_IDS,
    register(router: McpRouter): void {
      // -------------------------------------------------------------------
      // POST /v1/mcp — mcpJsonRpc (Streamable HTTP + SSE)
      // -------------------------------------------------------------------
      router.register("mcpJsonRpc", async (c) => {
        const ports = resolvePorts(c.env);
        const { requestId } = requestIdentity(c.req.raw);

        const body = await readCappedBody(c.req.raw);
        if (!body.ok) {
          return respondError(
            c,
            413,
            errorEnvelope(
              "payload_too_large",
              `request body exceeds maximum size of ${body.maxBytes} bytes`,
              requestId,
            ),
          );
        }

        // The required scope is a function of the JSON-RPC method, so the body
        // is parsed first — but NOTHING is executed before authentication.
        const planned = planIngress(c.req.raw.headers, body.body);
        if (!planned.ok) return respondJsonRpc(c.req.raw, planned.status, planned.response);

        // FC-1: the JSON-RPC endpoint is ONE contract operation carrying many
        // methods, so billability is decided per METHOD. `tools/call`,
        // `resources/read` and `prompts/get` reach a remote server and spend;
        // `initialize`, `ping`, `tools/list` and `resources/list` are handshake
        // and discovery, and a draining node must keep answering them or a
        // client cannot learn where to fail over to. See `../drain.ts`.
        const authenticated = await authenticateRequest(
          ports,
          c.req.raw,
          planned.plan.scope,
          "mcp",
          {
            billable: isDrainGuardedRpcMethod(planned.plan.request.method),
            env: c.env as DrainBindings,
          },
        );
        if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);

        // THE MOUNT. Upstreams are per-TENANT, so the real host can only be
        // built once the caller is authenticated — see `../upstreams.ts`.
        // Deleting this line silently reverts every deployment to the in-memory
        // host, which is why `test/durable-upstreams.test.ts` drives
        // `tools/list` over `SELF` and asserts a catalog only D1 can supply.
        const tenantPorts = await withTenantUpstreams(c.env, ports, authenticated.context.auth);

        // THE MOUNT of the UNIFIED CLIENT SESSION (#687). It is resolved AFTER
        // `withTenantUpstreams` on purpose: the upstream set a session binds is
        // read off the tenant's already-narrowed host, so a session can never
        // name an upstream its tenant is not entitled to. Deleting this call
        // returns the ingress to minting no `Mcp-Session-Id` and silently
        // ignoring every `Last-Event-ID`, which is the state #687 describes.
        const wantsStream = prefersEventStream(c.req.raw.headers.get("accept"));
        const session = await resolveUnifiedSession(
          c.env,
          c.req.raw.headers,
          tenantPorts,
          authenticated.context.auth,
          planned.plan.request.method,
          { wantsStream },
        );
        if (!session.ok) {
          return respondError(
            c,
            session.status,
            errorEnvelope(session.code, session.message, requestId),
          );
        }
        const binding = session.binding;

        // The upstreams that serve THIS request report themselves through the
        // dispatch context, so the replay log records the fan-out leg each
        // frame came from rather than the ingress guessing from a flat name.
        const attribution = binding === undefined ? undefined : attributionSink();
        const context =
          attribution === undefined
            ? authenticated.context
            : { ...authenticated.context, upstreams: attribution };

        const outcome = await dispatchMcpRequest(
          tenantPorts,
          c.req.raw.headers,
          planned.plan,
          context,
        );
        if (outcome.empty === true) {
          // A Notification carries no body, so there is no frame to log and no
          // cursor to hand out — but the session header still answers, because
          // a client must be able to tell an accepted notification from a
          // session it has lost.
          const headers =
            binding === undefined ? undefined : { [MCP_SESSION_ID_HEADER]: binding.sessionId };
          return new Response(null, { status: outcome.status, headers });
        }
        if (binding === undefined) {
          return respondJsonRpc(c.req.raw, outcome.status, outcome.response);
        }
        return await respondInSession(
          c.req.raw,
          outcome.status,
          outcome.response,
          binding,
          attribution as NonNullable<typeof attribution>,
          tenantPorts,
        );
      });

      /** Every other method on the JSON-RPC endpoint. */
      router.app.all("/v1/mcp", methodNotAllowed("MCP JSON-RPC endpoint requires POST"));

      // -------------------------------------------------------------------
      // POST /v1/mcp/tool/execute — executeMcpTool
      // -------------------------------------------------------------------
      /**
       * The REST transport for the same governed tool chokepoint the JSON-RPC
       * `tools/call` runs. The contract records this operation's auth as
       * `bearer + mcp.execute`; the Rust gateway spells that as the
       * `tools.execute` API-key scope PLUS the `mcp.execute` plan/RBAC
       * entitlement, and both are enforced here.
       */
      router.register("executeMcpTool", async (c) => {
        const ports = resolvePorts(c.env);
        const { requestId } = requestIdentity(c.req.raw);

        // FC-1: the REST transport of the same governed tool chokepoint
        // `tools/call` runs, so it spends and stops on the same operator drain.
        const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp", {
          billable: true,
          env: c.env as DrainBindings,
        });
        if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);
        const context = authenticated.context;

        const body = await readCappedBody(c.req.raw);
        if (!body.ok) {
          return respondError(
            c,
            413,
            errorEnvelope(
              "payload_too_large",
              `request body exceeds maximum size of ${body.maxBytes} bytes`,
              requestId,
            ),
          );
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(body.body);
        } catch (cause) {
          return respondError(
            c,
            400,
            errorEnvelope(
              "invalid_json",
              `invalid tool execution JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
              requestId,
            ),
          );
        }
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          return respondError(
            c,
            400,
            errorEnvelope("invalid_json", "tool execution body must be a JSON object", requestId),
          );
        }
        const object = parsed as Record<string, unknown>;
        const name = object["name"];
        if (typeof name !== "string") {
          return respondError(
            c,
            400,
            errorEnvelope("invalid_json", "tool execution requires a string name", requestId),
          );
        }

        const backend = isBuiltinTool(name) ? "builtin" : "mcp";

        // Plan/RBAC entitlement gate runs BEFORE the chokepoint, matching REST.
        const denial = await ports.entitlements.toolExecutionDenial(context.auth, backend);
        if (denial !== undefined) {
          return respondError(c, 403, errorEnvelope(denial.code, denial.message, requestId));
        }

        const request: ToolExecutionRequest = {
          name,
          arguments: (object["arguments"] ?? {}) as ToolExecutionRequest["arguments"],
        };
        const route = object["route"];
        if (typeof route === "string") request.route = route;
        const sessionId = object["session_id"];
        if (typeof sessionId === "string") request.sessionId = sessionId;
        // #687: the REST spelling of the JSON-RPC `_meta["ferrogate/server"]`
        // selector. `_meta` is a JSON-RPC-shaped envelope that has no place in
        // a REST body, so this transport takes the same string as a top-level
        // field — the two transports must agree about which upstream serves a
        // name or they are two different gateways.
        const server = object["server"];
        if (typeof server === "string" && server !== "") request.server = server;

        // THE MOUNT, on the REST transport of the same chokepoint. Both ingress
        // paths must resolve the tenant's real host or the two transports
        // disagree about which tools exist — see `../upstreams.ts`.
        const tenantPorts = await withTenantUpstreams(c.env, ports, context.auth);

        const executed = await executeToolWithGovernance(tenantPorts, context, request, backend);
        if (!executed.ok) {
          return respondError(
            c,
            executed.error.status,
            errorEnvelope(executed.error.code, executed.error.message, requestId),
          );
        }
        return c.json(executed.response);
      });

      router.app.all("/v1/mcp/tool/execute", methodNotAllowed("tool execution requires POST"));
    },
  };
}

/**
 * Answer with `application/json` or, when the caller prefers it, a
 * single-message `text/event-stream` — the two shapes Streamable HTTP permits
 * for a POST response.
 */
function respondJsonRpc(
  request: Request,
  status: number,
  response: JsonRpcResponse | undefined,
  extraHeaders: Record<string, string> = {},
  replay: readonly SseEvent[] = [],
  eventId?: string,
): Response {
  const payload = renderJsonRpcResponse(
    response ?? jsonRpcError(undefined, JsonRpcErrorCode.InternalError, "no response was produced"),
  );
  if (prefersEventStream(request.headers.get("accept"))) {
    const fresh: SseEvent = { event: "message", data: JSON.stringify(payload) };
    if (eventId !== undefined) fresh.id = eventId;
    return sseFrameResponse([...replay, fresh], { status, headers: extraHeaders });
  }
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

/**
 * Answer inside a unified client session (#687).
 *
 * Three things happen here that do not happen on the stateless path, in this
 * order and for these reasons:
 *
 *  1. the upstream health this request observed is written to the session, so
 *     an upstream that dropped mid-conversation is a fact the session holds
 *     rather than a detail of one response the client may have missed;
 *  2. the session facts are stamped onto the result's `_meta` — the same
 *     `_meta` vocabulary the multiplex contract already uses for the per-tool
 *     selector and the degraded-upstream report, rather than a second one;
 *  3. the rendered frame is APPENDED to the replay log, and the sequence the
 *     log allocates becomes the frame's `id:`. Appending after stamping is what
 *     makes the replayed bytes identical to the bytes the client first saw.
 */
async function respondInSession(
  request: Request,
  status: number,
  response: JsonRpcResponse | undefined,
  binding: UnifiedSessionBinding,
  attribution: ReturnType<typeof attributionSink>,
  ports: McpPorts,
): Promise<Response> {
  // An upstream that failed on THIS request has dropped its session
  // mid-conversation. Recording it on the session — not merely in this one
  // response — is what makes it a fact the client can still discover after a
  // reconnect. The client session itself is never invalidated by it.
  await binding.store.recordUpstreamHealth(binding.sessionId, attribution.failures);
  const dropped = attribution.failures.map((failure) => failure.server).sort();
  const facts = {
    sessionId: binding.sessionId,
    added: binding.reconcile?.added ?? [],
    removed: binding.reconcile?.removed ?? [],
    dropped:
      dropped.length > 0
        ? dropped
        : // A previously-dropped upstream that is back in the catalogue and
          // healthy is no longer reported, so the field means "broken NOW".
          (binding.reconcile?.dropped ?? []),
    ...(binding.minted
      ? { openedWith: ports.upstreams.listServers().map((config) => config.name) }
      : {}),
  };
  stampSessionMeta(response, facts);

  const payload = renderJsonRpcResponse(
    response ?? jsonRpcError(undefined, JsonRpcErrorCode.InternalError, "no response was produced"),
  );
  const seq = await binding.store.append(
    binding.sessionId,
    JSON.stringify(payload),
    attribution.servers,
  );
  const headers: Record<string, string> = { [MCP_SESSION_ID_HEADER]: binding.sessionId };
  const replay: SseEvent[] = binding.replay.map((frame) => ({
    event: "message",
    data: frame.payload,
    id: frameCursor(binding, frame.seq),
  }));
  return respondJsonRpc(
    request,
    status,
    response,
    headers,
    replay,
    seq === undefined ? undefined : frameCursor(binding, seq),
  );
}
