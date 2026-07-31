/**
 * `ferrogate-mcp` Worker — FerroGate's MCP host ingress.
 *
 * Clean-room re-implementation of the Rust `ferrogate-mcp` host and the
 * `/v1/mcp*` surface of `ferrogate-gateway` (`server/mcp_rpc.rs`,
 * `server/mcp_ingress.rs`, `server/mcp_identity.rs`), per
 * `docs/legacy/inventory-edge-control.md` §4 (MCP).
 *
 * The six contract operations this Worker owns
 * (docs/openapi/runtime-api-contract.json):
 *
 * | operation_id               | route                                      | auth                    |
 * |----------------------------|--------------------------------------------|-------------------------|
 * | `mcpJsonRpc`               | `POST /v1/mcp`                             | method_dependent scope  |
 * | `executeMcpTool`           | `POST /v1/mcp/tool/execute`                | bearer, MCP execute     |
 * | `getMcpIdentity`           | `GET /v1/mcp/identity/{server}`            | bearer `tools.read`     |
 * | `revokeMcpIdentity`        | `DELETE /v1/mcp/identity/{server}`         | bearer `tools.execute`  |
 * | `authorizeMcpIdentity`     | `POST /v1/mcp/identity/{server}/authorize` | bearer `tools.execute`  |
 * | `completeMcpIdentityOauth` | `GET /v1/mcp/identity/callback`            | anonymous (state-bound) |
 *
 * ## Why the JSON-RPC layer is hand-written rather than `@modelcontextprotocol/sdk`
 *
 * The SDK models a stateful MCP *server* (session ids, a resumable event log,
 * `initialize` handshake state). FerroGate's ingress is deliberately the
 * opposite: a STATELESS dual-era gateway that must (a) accept the pinned
 * `2026-07-28` candidate revision, which has no `initialize` handshake and adds
 * the `Mcp-Method` / `Mcp-Name` routing headers the SDK does not model, and (b)
 * fail a request CLOSED when a routing header disagrees with the body — a
 * gateway-specific control with no SDK hook. Wrapping the SDK would mean
 * bypassing it for exactly the behavior this port exists to preserve, so
 * `src/jsonrpc.ts` implements the JSON-RPC 2.0 codec directly and
 * `src/transport.ts` implements both transport directions. The SDK stays a
 * declared dependency for the tenant-hosted MCP-server half (see below).
 *
 * PORT-TODO(inventory-edge-control §9.2): the OTHER half of the Rust crate —
 * `mcp_worker_deploy.rs`, which uploads a tenant's own hosted MCP-server Worker
 * (`FerroGateMcp extends McpAgent` at `/mcp` + `/sse` behind
 * `@cloudflare/workers-oauth-provider`) — becomes a `wrangler deploy` wrapper
 * in the control plane, not a runtime route here.
 */
import { Hono } from "hono";

import { PUBLIC_API_MAJOR } from "@ferrogate/core";

import { dispatchMcpRequest, planIngress } from "./dispatch.js";
import {
  authenticateRequest,
  errorEnvelope,
  readCappedBody,
  requestIdentity,
  respondError,
} from "./http.js";
import { identityRoutes } from "./identity/routes.js";
import {
  JsonRpcErrorCode,
  jsonRpcError,
  renderJsonRpcResponse,
  type JsonRpcResponse,
} from "./jsonrpc.js";
import { resolvePorts, type McpEnv } from "./ports.js";
import { executeToolWithGovernance, isBuiltinTool, type ToolExecutionRequest } from "./tools.js";
import { prefersEventStream, sseJsonRpcResponse } from "./transport.js";

const app = new Hono<{ Bindings: McpEnv }>();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) =>
  c.json({ api: PUBLIC_API_MAJOR, protocol: "2026-07-28", transports: ["streamable_http", "sse"] }),
);

// ---------------------------------------------------------------------------
// POST /v1/mcp — mcpJsonRpc (Streamable HTTP + SSE)
// ---------------------------------------------------------------------------

app.post("/v1/mcp", async (c) => {
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

  // The required scope is a function of the JSON-RPC method, so the body is
  // parsed first — but NOTHING is executed before authentication.
  const planned = planIngress(c.req.raw.headers, body.body);
  if (!planned.ok) return respondJsonRpc(c.req.raw, planned.status, planned.response);

  const authenticated = await authenticateRequest(ports, c.req.raw, planned.plan.scope, "mcp");
  if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);

  const outcome = await dispatchMcpRequest(
    ports,
    c.req.raw.headers,
    planned.plan,
    authenticated.context,
  );
  if (outcome.empty === true) return new Response(null, { status: outcome.status });
  return respondJsonRpc(c.req.raw, outcome.status, outcome.response);
});

/** Every other method on the JSON-RPC endpoint. */
app.all("/v1/mcp", (c) => {
  const { requestId } = requestIdentity(c.req.raw);
  return respondError(
    c,
    405,
    errorEnvelope("method_not_allowed", "MCP JSON-RPC endpoint requires POST", requestId),
  );
});

// ---------------------------------------------------------------------------
// POST /v1/mcp/tool/execute — executeMcpTool
// ---------------------------------------------------------------------------

/**
 * The REST transport for the same governed tool chokepoint the JSON-RPC
 * `tools/call` runs. The contract records this operation's auth as
 * `bearer + mcp.execute`; the Rust gateway spells that as the `tools.execute`
 * API-key scope PLUS the `mcp.execute` plan/RBAC entitlement, and both are
 * enforced here.
 */
app.post("/v1/mcp/tool/execute", async (c) => {
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

  const executed = await executeToolWithGovernance(ports, context, request, backend);
  if (!executed.ok) {
    return respondError(
      c,
      executed.error.status,
      errorEnvelope(executed.error.code, executed.error.message, requestId),
    );
  }
  return c.json(executed.response);
});

app.all("/v1/mcp/tool/execute", (c) => {
  const { requestId } = requestIdentity(c.req.raw);
  return respondError(
    c,
    405,
    errorEnvelope("method_not_allowed", "tool execution requires POST", requestId),
  );
});

// ---------------------------------------------------------------------------
// /v1/mcp/identity/** — the four identity operations
// ---------------------------------------------------------------------------

app.route("/v1/mcp/identity", identityRoutes);

// ---------------------------------------------------------------------------
// Fallbacks
// ---------------------------------------------------------------------------

app.notFound((c) => {
  const { requestId } = requestIdentity(c.req.raw);
  return respondError(c, 404, errorEnvelope("not_found", "no such route", requestId));
});

app.onError((error, c) => {
  const { requestId } = requestIdentity(c.req.raw);
  // Never leak an internal message across the boundary.
  console.error("ferrogate-mcp unhandled error", error);
  return respondError(
    c,
    500,
    errorEnvelope("internal_error", "the MCP gateway could not complete this request", requestId),
  );
});

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

export default app;

export { app };
