/**
 * ONE contract-driven auth middleware for all 251 operations.
 *
 * `ROUTE-MAP.md` invariant 1: "Port these as Hono middleware driven by the
 * contract, not as hand-written per-route guards — one table-driven middleware
 * keeps all 251 in sync." This is that middleware. It matches the request
 * against `contract.ts`, then enforces whatever the matched operation *declares*
 * (`auth.kind`, `auth.scope`, `rbac_action`). Adding a route to the contract
 * automatically brings its guard with it; nothing here mentions a specific path.
 *
 * Ported from `crates/ferrogate-gateway/src/auth.rs` +
 * `server/handlers.rs::handle_request_filter`. The status/code taxonomy is
 * reproduced exactly, including the two invariants that were real Rust defect
 * classes:
 *
 *  - **A suspended native API key is 401, not 403.** In Rust the durable
 *    authenticator returns `None` for a key that is `!enabled` / revoked /
 *    expired, so the request falls through to the same
 *    `401 invalid_api_key` a completely unknown key gets. Key *state* is not
 *    disclosed. (Static, operator-authored config keys are different: they
 *    report `403 api_key_disabled` / `403 api_key_expired`. Both live in
 *    `ApiKeyResolution`.) Distinct again from *tenancy* suspension, which is an
 *    authenticated-but-forbidden 403 `tenancy_suspended`.
 *  - **`internal` is not reachable with a tenant bearer.** The 6
 *    `/v1/self-hosted-workers/*` callbacks never consult the API-key
 *    authenticator at all; they are verified solely by the worker-plane
 *    transport port. There is no code path from a tenant bearer to an internal
 *    operation.
 */
import type { MiddlewareHandler } from "hono";
import {
  type ApiOperation,
  canonicalRequestPath,
  matchOperation,
  methodDependentScope,
  pathIsDocumented,
} from "../contract.js";
import {
  type ApiKeyResolution,
  type AuthContext,
  type GatewayBindings,
  type GatewayDeps,
  type GatewayEnv,
  hasScope,
} from "../ports.js";
import { HttpError } from "./errors.js";

/**
 * Rust `auth::extract_api_key`: `x-api-key` wins over `Authorization: Bearer`,
 * both trimmed, and a blank value counts as absent.
 */
export function extractApiKey(headers: Headers): string | null {
  const apiKeyHeader = headers.get("x-api-key");
  if (apiKeyHeader !== null) {
    const trimmed = apiKeyHeader.trim();
    if (trimmed !== "") return trimmed;
  }
  const authorization = headers.get("authorization");
  if (authorization === null) return null;
  const value = authorization.trim();
  if (!value.startsWith("Bearer ")) return null;
  const token = value.slice("Bearer ".length).trim();
  return token === "" ? null : token;
}

/** The Rust message for an absent credential, verbatim. */
const MISSING_API_KEY_MESSAGE = "missing API key; use Authorization: Bearer or x-api-key";

/**
 * `ApiKeyResolution` → the `AuthContext` or the exact Rust refusal.
 *
 * `unknown` and `key_suspended` deliberately collapse onto the SAME
 * `401 invalid_api_key`: that indistinguishability is the invariant.
 */
function resolveOrThrow(resolution: ApiKeyResolution): AuthContext {
  switch (resolution.outcome) {
    case "resolved":
      return resolution.auth;
    case "unknown":
    case "key_suspended":
      throw new HttpError(401, "invalid_api_key", "invalid API key");
    case "static_key_disabled":
      throw new HttpError(403, "api_key_disabled", "API key is disabled");
    case "static_key_expired":
      throw new HttpError(403, "api_key_expired", "API key is expired");
    case "token_budget_exhausted":
      throw new HttpError(429, "token_budget_exceeded", "API key token budget is exhausted");
    case "unavailable":
      throw new HttpError(
        503,
        "external_auth_unavailable",
        `external auth service is unavailable: ${resolution.detail}`,
      );
  }
}

/**
 * Resolve the scope a `method_dependent` operation requires, from the request
 * body field the contract's `scope_discriminator` names (today: the JSON-RPC
 * `method` of `POST /v1/mcp`).
 *
 * Fails closed. Rust's `mcp_rpc::required_scope` raises `MissingScopeMapping`
 * when the contract has no entry for the presented value; an unmapped value
 * must never be read as "no scope required".
 */
async function methodDependentRequiredScope(
  request: Request,
  operation: ApiOperation,
  path: string,
): Promise<string> {
  const discriminator = operation.auth.scopeDiscriminator;
  if (discriminator === null) {
    throw new HttpError(
      500,
      "internal_error",
      `operation ${operation.operationId} is method_dependent without a scope discriminator`,
    );
  }

  let value: unknown;
  try {
    // Hono caches the parsed body, so the downstream handler can read it again.
    const body: unknown = await request.clone().json();
    value =
      typeof body === "object" && body !== null
        ? (body as Record<string, unknown>)[discriminator.field]
        : undefined;
  } catch {
    throw new HttpError(400, "invalid_request", "request body must be JSON");
  }

  if (typeof value !== "string" || value === "") {
    throw new HttpError(
      400,
      "invalid_request",
      `request body field ${discriminator.field} is required`,
    );
  }

  const scope = methodDependentScope(operation.method, path, value);
  if (scope === undefined) {
    // PORT-TODO(inventory-request-path §MCP): a CROSS-APP boundary, not a gap
    // in this file. For `POST /v1/mcp` the JSON-RPC-native answer to an unknown
    // `method` is error -32601 ("method not found") in a 200 envelope, and
    // `apps/mcp` — which owns the MCP dialect — may well want that. It cannot
    // be produced HERE: this middleware guards all 251 contract operations and
    // knows nothing about JSON-RPC framing, and emitting a 200 from the auth
    // boundary for an unrecognised discriminator would mean an unauthenticated
    // caller could probe method names.
    // The contract carries no scope for the value, so the only safe answer at
    // the auth boundary is a denial, and 403 `scope_denied` is the one that is
    // true: the credential was accepted, the operation was not.
    throw new HttpError(
      403,
      "scope_denied",
      `runtime API contract has no scope mapping for ${discriminator.field} ${value}`,
    );
  }
  return scope;
}

/** Ports, or a factory that derives them from the Worker bindings per request. */
export type DepsResolver = GatewayDeps | ((env: GatewayBindings) => GatewayDeps);

/**
 * The table-driven guard. Mount it once, before every route:
 * `app.use("*", contractAuth(deps))`.
 *
 * `deps` may be a factory because Worker bindings only exist per request; the
 * factory is called inside the middleware rather than by an enclosing wrapper.
 * That is deliberate: an `async` wrapper that merely *returns* this middleware's
 * promise adds a promise-adoption hop, and a guard that rejects before its first
 * `await` (a missing credential, a 405) then surfaces in workerd as an unhandled
 * rejection even though Hono's `onError` handles it. One function, no hop.
 *
 * Requests whose path is not in the contract pass straight through — the
 * `dynamic_surfaces` (operator-defined reverse-proxy routes, `OPTIONS /admin/*`)
 * are data, not contract, and are guarded by their own config-driven policy.
 */
export function contractAuth(deps: DepsResolver): MiddlewareHandler<GatewayEnv> {
  return async function contractAuthMiddleware(c, next) {
    const ports: GatewayDeps = typeof deps === "function" ? deps(c.env) : deps;
    // `/control/v1/*` → `/admin/v1/*` before ANY matching (ROUTE-MAP invariant 7,
    // Rust folds the alias at request ingress so both prefixes observe one
    // contract, one guard, one set of error codes).
    const path = canonicalRequestPath(c.req.path);
    c.set("canonicalPath", path);

    const matched = matchOperation(c.req.method, path);
    if (matched === undefined) {
      if (pathIsDocumented(path)) {
        // Rust: a documented path reached with an undocumented method is 405,
        // decided before authentication.
        throw new HttpError(
          405,
          "method_not_allowed",
          `${c.req.method} is not documented for ${path}`,
        );
      }
      await next();
      return;
    }

    const operation = matched.operation;
    c.set("operation", operation);

    // --- anonymous: the only 6 operations that may skip auth ----------------
    if (operation.auth.kind === "anonymous") {
      await next();
      return;
    }

    // --- internal: worker-plane transport ONLY ------------------------------
    // No bearer is consulted here, by construction. A tenant key — even a
    // platform-operator one — cannot satisfy an internal operation.
    if (operation.auth.kind === "internal") {
      const decision = await ports.internalTransport.verify(c.req.raw, operation);
      if (!decision.verified) {
        throw new HttpError(decision.status, decision.code, decision.message);
      }
      c.set("workerIdentity", decision.identity);
      await next();
      return;
    }

    // --- bearer / method_dependent ------------------------------------------
    const requiredScope =
      operation.auth.kind === "method_dependent"
        ? await methodDependentRequiredScope(c.req.raw, operation, path)
        : operation.auth.scope;

    if (requiredScope === null) {
      throw new HttpError(
        500,
        "internal_error",
        `operation ${operation.operationId} uses bearer auth without a scope`,
      );
    }

    const presentedKey = extractApiKey(c.req.raw.headers);
    if (presentedKey === null) {
      throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
    }

    const auth = resolveOrThrow(await ports.apiKeys.authenticate(presentedKey));

    // Authenticated but under-scoped is 403 — never 401.
    if (!hasScope(auth.scopes, requiredScope)) {
      throw new HttpError(
        403,
        "scope_denied",
        `API key does not have required scope ${requiredScope}`,
      );
    }

    // Tenancy lifecycle: a suspended/deleted TENANT is authenticated-but-
    // forbidden (403 `tenancy_suspended`), distinct from a suspended KEY (401).
    const lifecycle = await ports.lifecycle.admit(auth, operation);
    if (!lifecycle.admitted) {
      throw new HttpError(403, lifecycle.code, lifecycle.message);
    }

    if (operation.rbacAction !== null) {
      const decision = await ports.rbac.authorize(auth, operation.rbacAction);
      if (decision.allowed === "unavailable") {
        throw new HttpError(
          503,
          "rbac_unavailable",
          `failed to resolve role permissions: ${decision.detail}`,
        );
      }
      if (!decision.allowed) {
        throw new HttpError(403, decision.code, decision.message);
      }
    }

    c.set("auth", auth);
    await next();
  };
}
