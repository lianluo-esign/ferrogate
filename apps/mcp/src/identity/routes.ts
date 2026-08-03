/**
 * The per-user MCP identity control-plane endpoints.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/mcp_identity.rs`.
 *
 * Contract operations (docs/openapi/runtime-api-contract.json):
 *   GET    /v1/mcp/identity/callback           completeMcpIdentityOauth  (anonymous)
 *   POST   /v1/mcp/identity/{server}/authorize authorizeMcpIdentity      (bearer tools.execute)
 *   GET    /v1/mcp/identity/{server}           getMcpIdentity            (bearer tools.read)
 *   DELETE /v1/mcp/identity/{server}           revokeMcpIdentity         (bearer tools.execute)
 *
 * The callback is deliberately ANONYMOUS: the identity provider redirects the
 * end user's browser here with no FerroGate credential. Its authorization is
 * carried entirely by the single-use, time-bounded, sha256-keyed `state` and
 * the OIDC subject binding inside {@link completeMcpOauth} — which is why that
 * function must never be relaxed.
 *
 * These four are mounted on the SAME router as the ingress operations, at the
 * contract's own paths, rather than as a sub-app mounted under a hand-written
 * prefix: the prefix was a second place a path could drift from the contract,
 * and a sub-app is invisible to the registry the anti-drift gate reads.
 */
import type { Context } from "hono";

import type { DrainBindings } from "../drain.js";
import { authenticateRequest, errorEnvelope, requestIdentity, respondError } from "../http.js";
import { resolvePorts } from "../ports.js";
import {
  type McpAppEnv,
  type McpRouter,
  type RouteModule,
  methodNotAllowed,
} from "../routes/index.js";
import { auditEvent } from "../tools.js";
import {
  McpIdentityError,
  completeMcpOauth,
  mcpIdentityStatus,
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

/** Contract operations this module mounts. */
export const IDENTITY_OPERATION_IDS = [
  "completeMcpIdentityOauth",
  "authorizeMcpIdentity",
  "getMcpIdentity",
  "revokeMcpIdentity",
] as const;

export function identityRouteModule(): RouteModule {
  return {
    name: "identity",
    operationIds: IDENTITY_OPERATION_IDS,
    register(router: McpRouter): void {
      /**
       * `GET /v1/mcp/identity/callback` — registered BEFORE `/:server` so the
       * literal `callback` segment can never be captured as a server name.
       */
      router.register("completeMcpIdentityOauth", async (c) => {
        const ports = resolvePorts(c.env);
        const { requestId, traceId } = requestIdentity(c.req.raw);
        const url = new URL(c.req.url);
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        // RFC 9207 (SEP-2468). OPTIONAL on the wire — an authorization server
        // that predates the RFC omits it — so it is read, never required, and
        // `completeMcpOauth` owns the decision about a present value.
        const iss = url.searchParams.get("iss");
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
            ...(iss === null ? {} : { iss }),
            requestId,
            ...(traceId === undefined ? {} : { traceId }),
          });
          return c.json(view);
        } catch (cause) {
          return identityFailure(c, cause, requestId);
        }
      });

      /** Any other method on the callback path. */
      router.app.all(
        "/v1/mcp/identity/callback",
        methodNotAllowed("MCP OAuth callback requires GET"),
      );

      /** `POST /v1/mcp/identity/{server}/authorize` — start a per-user OAuth flow. */
      router.register("authorizeMcpIdentity", async (c) => {
        const ports = resolvePorts(c.env);
        // The router mounts the contract path `/v1/mcp/identity/{server}`, so
        // the capture is always present; `?? ""` keeps that assumption from
        // becoming a silent `undefined` — an empty segment fails
        // `validServerSegment` and answers 404 like any other bad name.
        const serverName = c.req.param("server") ?? "";
        const { requestId } = requestIdentity(c.req.raw);
        if (!validServerSegment(serverName)) return notFound(c, requestId);

        const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp", {
          // FC-1: starting an OAuth authorization flow reaches the identity
          // provider, not a paid upstream, and it is how an operator repairs a
          // broken connection. It keeps serving while draining.
          billable: false,
          env: c.env as DrainBindings,
        });
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
      router.register("getMcpIdentity", async (c) => {
        const ports = resolvePorts(c.env);
        // The router mounts the contract path `/v1/mcp/identity/{server}`, so
        // the capture is always present; `?? ""` keeps that assumption from
        // becoming a silent `undefined` — an empty segment fails
        // `validServerSegment` and answers 404 like any other bad name.
        const serverName = c.req.param("server") ?? "";
        const { requestId } = requestIdentity(c.req.raw);
        if (!validServerSegment(serverName)) return notFound(c, requestId);

        const authenticated = await authenticateRequest(ports, c.req.raw, "tools.read", "mcp", {
          // FC-1: a connection-status READ. No spend, and refusing it during a
          // drain would hide the state an operator is draining to inspect.
          billable: false,
          env: c.env as DrainBindings,
        });
        if (!authenticated.ok) return respondError(c, authenticated.status, authenticated.body);

        try {
          return c.json(await mcpIdentityStatus(ports, authenticated.context, serverName));
        } catch (cause) {
          return identityFailure(c, cause, requestId);
        }
      });

      /** `DELETE /v1/mcp/identity/{server}` — revoke the per-user grant. */
      router.register("revokeMcpIdentity", async (c) => {
        const ports = resolvePorts(c.env);
        // The router mounts the contract path `/v1/mcp/identity/{server}`, so
        // the capture is always present; `?? ""` keeps that assumption from
        // becoming a silent `undefined` — an empty segment fails
        // `validServerSegment` and answers 404 like any other bad name.
        const serverName = c.req.param("server") ?? "";
        const { requestId } = requestIdentity(c.req.raw);
        if (!validServerSegment(serverName)) return notFound(c, requestId);

        const authenticated = await authenticateRequest(ports, c.req.raw, "tools.execute", "mcp", {
          // FC-1: a REVOCATION. It must keep working while draining — an
          // operator draining a deployment during a credential incident still
          // has to be able to revoke, and a revoke removes access rather than
          // spending on it.
          billable: false,
          env: c.env as DrainBindings,
        });
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
      router.app.all(
        "/v1/mcp/identity/:server",
        methodNotAllowed("unsupported MCP identity method"),
      );
    },
  };
}

function notFound(c: Context<McpAppEnv>, requestId: string): Response {
  return respondError(
    c,
    404,
    errorEnvelope("mcp_identity_not_found", "MCP identity endpoint was not found", requestId),
  );
}

function identityFailure(c: Context<McpAppEnv>, cause: unknown, requestId: string): Response {
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
