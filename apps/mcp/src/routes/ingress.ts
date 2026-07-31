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
import { resolvePorts } from "../ports.js";
import { type ToolExecutionRequest, executeToolWithGovernance, isBuiltinTool } from "../tools.js";
import { prefersEventStream, sseJsonRpcResponse } from "../transport.js";
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

        const authenticated = await authenticateRequest(
          ports,
          c.req.raw,
          planned.plan.scope,
          "mcp",
        );
        if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);

        // THE MOUNT. Upstreams are per-TENANT, so the real host can only be
        // built once the caller is authenticated — see `../upstreams.ts`.
        // Deleting this line silently reverts every deployment to the in-memory
        // host, which is why `test/durable-upstreams.test.ts` drives
        // `tools/list` over `SELF` and asserts a catalog only D1 can supply.
        const tenantPorts = await withTenantUpstreams(c.env, ports, authenticated.context.auth);

        const outcome = await dispatchMcpRequest(
          tenantPorts,
          c.req.raw.headers,
          planned.plan,
          authenticated.context,
        );
        if (outcome.empty === true) return new Response(null, { status: outcome.status });
        return respondJsonRpc(c.req.raw, outcome.status, outcome.response);
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

        const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp");
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
): Response {
  const payload = renderJsonRpcResponse(
    response ?? jsonRpcError(undefined, JsonRpcErrorCode.InternalError, "no response was produced"),
  );
  if (prefersEventStream(request.headers.get("accept"))) {
    return sseJsonRpcResponse(payload, { status });
  }
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}
