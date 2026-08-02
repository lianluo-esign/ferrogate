/**
 * ONE contract-driven auth middleware for all 197 control-plane operations.
 *
 * `ROUTE-MAP.md` invariant 1: "Port these as Hono middleware driven by the
 * contract, not as hand-written per-route guards — one table-driven middleware
 * keeps all 252 in sync." This is that middleware for this Worker's slice. It
 * matches the request against `contract.ts`, then enforces whatever the matched
 * operation *declares* (`auth.kind`, `auth.scope`, `rbac_action`). Adding an
 * operation to the contract brings its guard with it; nothing here names a path.
 *
 * Ported from `crates/ferrogate-gateway/src/auth.rs::authenticate_with_admission`
 * and `server/guardrail_policies.rs::require_guardrail_auth`. The status/code
 * taxonomy is reproduced exactly, including the invariants that were real Rust
 * defect classes:
 *
 *  - **A suspended native API key is 401, not 403.** The durable authenticator
 *    returns `None` for a key that is `!enabled` / revoked / expired, so the
 *    request falls through the static-config loop to the same
 *    `401 invalid_api_key` a completely unknown key gets. Key *state* is never
 *    disclosed. (Operator-authored *static config* keys are different and DO
 *    report `403 api_key_disabled` / `403 api_key_expired`; both live in
 *    `ApiKeyResolution`.) Distinct again from *tenancy* suspension, which is an
 *    authenticated-but-forbidden `403 tenancy_suspended`.
 *  - **Insufficient scope is 403, never 401.** The credential authenticated;
 *    it is the authorization that failed.
 *  - **`GET /metrics` is `visibility: internal` but `auth.kind: bearer`.** It is
 *    guarded here like every other bearer operation, by the same table — there
 *    is no "internal means unauthenticated" carve-out. Rust:
 *    `handle_metrics` → `authenticate(&state, headers, "admin.read", …)`.
 *  - **`rbac_action` is a second gate after the scope check.** A platform
 *    operator skips it; a tenant-scoped caller must clear its tenant's role
 *    grant, and an unavailable RBAC store is `503`, never an implicit allow.
 */
import type { MiddlewareHandler } from "hono";
import {
  canonicalRequestPath,
  matchOperation,
  methodsForPath,
  pathIsDocumented,
} from "../contract.js";
import {
  type ApiKeyResolution,
  type AuthContext,
  type ControlPlaneDeps,
  type ControlPlaneEnv,
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
export const MISSING_API_KEY_MESSAGE = "missing API key; use Authorization: Bearer or x-api-key";

/**
 * `ApiKeyResolution` → the `AuthContext`, or the exact Rust refusal.
 *
 * `unknown` and `key_suspended` deliberately collapse onto the SAME
 * `401 invalid_api_key`. That indistinguishability IS the invariant — do not
 * "improve" it into a 403 with a reason, which is the defect this port exists
 * to avoid reintroducing.
 */
export function resolveOrThrow(resolution: ApiKeyResolution): AuthContext {
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
 * CSRF / confused-deputy defense for admin mutations, ported verbatim from
 * `server/handlers.rs::admin_cross_site_rejection`.
 *
 * `Sec-Fetch-Site` is authoritative when present — every modern browser sends
 * it and page JavaScript cannot forge it (it is a forbidden header):
 * `cross-site`/`same-site` are rejected, `same-origin`/`none` allowed. When it
 * is absent the caller is either a non-browser client (no `Origin` → allowed:
 * curl, the SDKs, the CLI, these tests) or an older browser, in which case a
 * present `Origin` must equal the configured admin-console origin.
 */
export function adminCrossSiteRejection(
  headers: Headers,
  corsAllowedOrigin: string | null,
): string | null {
  const site = headers.get("sec-fetch-site");
  if (site !== null) {
    const normalized = site.toLowerCase();
    if (normalized === "cross-site" || normalized === "same-site") {
      return "cross-site admin mutations are not permitted";
    }
    return null;
  }
  const origin = headers.get("origin");
  if (origin !== null && origin !== corsAllowedOrigin) {
    return "cross-origin admin mutations are not permitted";
  }
  return null;
}

/** Rust `admin_method_is_state_changing` — safe methods and OPTIONS excluded. */
export function isStateChangingMethod(method: string): boolean {
  const upper = method.toUpperCase();
  return upper === "POST" || upper === "PUT" || upper === "PATCH" || upper === "DELETE";
}

/**
 * The table-driven guard. Mount once, before every route:
 * `app.use("*", contractAuth())`.
 *
 * Reads its dependencies from `c.get("deps")` so a test can swap the whole
 * composition root per request without rebuilding the app.
 *
 * Requests whose path is not in this Worker's contract slice pass straight
 * through to Hono's `notFound`; the `dynamic_surfaces` (`OPTIONS /admin/{*rest}`)
 * are data, not contract, and are handled by `./cors.ts` ahead of this.
 */
export function contractAuth(): MiddlewareHandler<ControlPlaneEnv> {
  return async function contractAuthMiddleware(c, next) {
    const deps: ControlPlaneDeps = c.get("deps");
    // The alias fold already happened at the fetch boundary; this is belt-and-
    // braces for a Hono app mounted directly (e.g. `app.request()` in a test).
    const path = canonicalRequestPath(c.req.path);
    c.set("canonicalPath", path);

    const matched = matchOperation(c.req.method, path);
    if (matched === undefined) {
      if (pathIsDocumented(path)) {
        // Rust: a documented path reached with an undocumented method is 405,
        // decided BEFORE authentication (the method is not a secret).
        const allow = methodsForPath(path).join(", ");
        const error = new HttpError(
          405,
          "method_not_allowed",
          `${c.req.method} is not documented for ${path}`,
        );
        c.header("allow", allow);
        throw error;
      }
      await next();
      return;
    }

    const operation = matched.operation;
    c.set("operation", operation);

    // --- CSRF: browser cross-site admin mutations, regardless of auth mode ---
    if (isStateChangingMethod(operation.method)) {
      const reason = adminCrossSiteRejection(c.req.raw.headers, deps.corsAllowedOrigin);
      if (reason !== null) throw new HttpError(403, "cross_site_admin_denied", reason);
    }

    // --- anonymous: /admin, /admin/, /admin/dashboard only -------------------
    if (operation.auth.kind === "anonymous") {
      await next();
      return;
    }

    // --- internal: not reachable on this Worker -----------------------------
    // The 6 `auth.kind: "internal"` operations live in apps/agent-runtime. If
    // one ever lands in this app's slice it must NOT fall through to the bearer
    // path, which would make it reachable with an ordinary tenant key.
    if (operation.auth.kind !== "bearer") {
      throw new HttpError(
        500,
        "internal_error",
        `operation ${operation.operationId} declares unsupported auth kind ${operation.auth.kind} on the control plane`,
      );
    }

    const requiredScope = operation.auth.scope;
    if (requiredScope === null) {
      // Unreachable: `contract.ts` refuses the document at load. Kept as a
      // fail-closed guard rather than a non-null assertion.
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

    const auth = resolveOrThrow(await deps.apiKeys.authenticate(presentedKey));

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
    //
    // A lifecycle store that cannot answer is 503, NEVER an implicit allow —
    // Rust `LifecycleGateError::Unavailable`. Fail-open here would make "flap
    // the control plane" a suspension bypass, so the unavailable branch is
    // handled BEFORE the admitted check (`"unavailable"` is truthy, so a bare
    // `!lifecycle.admitted` would wave it straight through).
    const lifecycle = await deps.lifecycle.admit(auth, operation);
    if (lifecycle.admitted === "unavailable") {
      throw new HttpError(
        503,
        "lifecycle_status_unavailable",
        `failed to resolve tenancy lifecycle: ${lifecycle.detail}`,
      );
    }
    if (!lifecycle.admitted) throw new HttpError(403, lifecycle.code, lifecycle.message);

    if (operation.rbacAction !== null) {
      const decision = await deps.rbac.authorize(auth, operation.rbacAction);
      if (decision.allowed === "unavailable") {
        throw new HttpError(
          503,
          "rbac_unavailable",
          `failed to resolve role permissions: ${decision.detail}`,
        );
      }
      if (!decision.allowed) throw new HttpError(403, decision.code, decision.message);
    }

    c.set("auth", auth);
    await next();
  };
}
