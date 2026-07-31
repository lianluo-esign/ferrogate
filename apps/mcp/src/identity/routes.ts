/**
 * The per-user MCP identity control-plane endpoints.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/mcp_identity.rs`.
 *
 * Contract operations (docs/openapi/runtime-api-contract.json):
 *   GET    /v1/mcp/identity/callback          completeMcpIdentityOauth  (anonymous)
 *   POST   /v1/mcp/identity/{server}/authorize authorizeMcpIdentity     (bearer tools.execute)
 *   GET    /v1/mcp/identity/{server}           getMcpIdentity           (bearer tools.read)
 *   DELETE /v1/mcp/identity/{server}           revokeMcpIdentity        (bearer tools.execute)
 *
 * The callback is deliberately ANONYMOUS: the identity provider redirects the
 * end user's browser here with no FerroGate credential. Its authorization is
 * carried entirely by the single-use, time-bounded, sha256-keyed `state` and
 * the OIDC subject binding inside {@link completeMcpOauth} — which is why that
 * function must never be relaxed.
 */
import { Hono, type Context } from "hono";

import { authenticateRequest, errorEnvelope, requestIdentity, respondError } from "../http.js";
import { resolvePorts, type McpEnv } from "../ports.js";
import { auditEvent } from "../tools.js";
import {
  completeMcpOauth,
  mcpIdentityStatus,
  McpIdentityError,
  revokeMcpIdentity,
  startMcpOauth,
} from "./oauth.js";

/** Scope required per method. Port of `handle_mcp_identity`'s `required_scope`. */
export function identityRequiredScope(method: string): string {
  return method === "GET" ? "tools.read" : "tools.execute";
}

/** A `{server}` path segment must be a single, non-empty, unnested name. */
export function validServerSegment(segment: string): boolean {
  return segment.length > 0 && !segment.includes("/");
}

export const identityRoutes = new Hono<{ Bindings: McpEnv }>();

/**
 * `GET /v1/mcp/identity/callback` — registered BEFORE `/:server` so the literal
 * `callback` segment can never be captured as a server name.
 */
identityRoutes.get("/callback", async (c) => {
  const ports = resolvePorts(c.env);
  const { requestId, traceId } = requestIdentity(c.req.raw);
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (code === null || state === null || code.length === 0 || state.length === 0) {
    return respondError(
      c,
      400,
      errorEnvelope(
        "mcp_oauth_callback_invalid",
        "OAuth callback requires code and state",
        requestId,
      ),
    );
  }
  try {
    const view = await completeMcpOauth(ports, {
      state,
      code,
      requestId,
      ...(traceId === undefined ? {} : { traceId }),
    });
    return c.json(view);
  } catch (cause) {
    return identityFailure(c, cause, requestId);
  }
});

/** Any other method on the callback path. */
identityRoutes.all("/callback", (c) => {
  const { requestId } = requestIdentity(c.req.raw);
  return respondError(
    c,
    405,
    errorEnvelope("method_not_allowed", "MCP OAuth callback requires GET", requestId),
  );
});

/** `POST /v1/mcp/identity/{server}/authorize` — start a per-user OAuth flow. */
identityRoutes.post("/:server/authorize", async (c) => {
  const ports = resolvePorts(c.env);
  const serverName = c.req.param("server");
  const { requestId } = requestIdentity(c.req.raw);
  if (!validServerSegment(serverName)) return notFound(c, requestId);

  const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp");
  if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);
  const context = authenticated.context;
  const target = `mcp:${serverName}/identity`;

  try {
    const view = await startMcpOauth(ports, context, serverName);
    ports.audit.record(
      auditEvent(
        context,
        "mcp.identity.authorize",
        target,
        "created",
        `server=${serverName} decision=allow authorization flow created`,
      ),
    );
    return c.json(view);
  } catch (cause) {
    const code = cause instanceof McpIdentityError ? cause.code : "mcp_identity_unavailable";
    ports.audit.record(
      auditEvent(
        context,
        "mcp.identity.authorize",
        target,
        "rejected",
        `server=${serverName} decision=deny code=${code}`,
      ),
    );
    return identityFailure(c, cause, requestId);
  }
});

/** `GET /v1/mcp/identity/{server}` — read the connection status. */
identityRoutes.get("/:server", async (c) => {
  const ports = resolvePorts(c.env);
  const serverName = c.req.param("server");
  const { requestId } = requestIdentity(c.req.raw);
  if (!validServerSegment(serverName)) return notFound(c, requestId);

  const authenticated = await authenticateRequest(ports, c.req.raw, "tools.read", "mcp");
  if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);

  try {
    return c.json(await mcpIdentityStatus(ports, authenticated.context, serverName));
  } catch (cause) {
    return identityFailure(c, cause, requestId);
  }
});

/** `DELETE /v1/mcp/identity/{server}` — revoke the per-user grant. */
identityRoutes.delete("/:server", async (c) => {
  const ports = resolvePorts(c.env);
  const serverName = c.req.param("server");
  const { requestId } = requestIdentity(c.req.raw);
  if (!validServerSegment(serverName)) return notFound(c, requestId);

  const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp");
  if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);
  const context = authenticated.context;

  try {
    const view = await revokeMcpIdentity(ports, context, serverName);
    ports.audit.record(
      auditEvent(
        context,
        "mcp.identity.revoke",
        `mcp:${serverName}/identity`,
        "revoked",
        `server=${serverName} subject=${view.subject ?? "unknown"} decision=allow`,
      ),
    );
    return c.json(view);
  } catch (cause) {
    return identityFailure(c, cause, requestId);
  }
});

/** Every other method on `/{server}`. */
identityRoutes.all("/:server", (c) => {
  const { requestId } = requestIdentity(c.req.raw);
  return respondError(
    c,
    405,
    errorEnvelope("method_not_allowed", "unsupported MCP identity method", requestId),
  );
});

function notFound(c: Context, requestId: string): Response {
  return respondError(
    c,
    404,
    errorEnvelope("mcp_identity_not_found", "MCP identity endpoint was not found", requestId),
  );
}

function identityFailure(c: Context, cause: unknown, requestId: string): Response {
  if (cause instanceof McpIdentityError) {
    return respondError(c, cause.status, errorEnvelope(cause.code, cause.message, requestId));
  }
  // An unmapped failure must not leak an internal message to the caller.
  return respondError(
    c,
    503,
    errorEnvelope(
      "mcp_identity_unavailable",
      "MCP identity operation could not be completed",
      requestId,
    ),
  );
}
