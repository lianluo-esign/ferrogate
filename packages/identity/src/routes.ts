/**
 * THE MOUNT SEAM.
 *
 * A composition root mounts this sub-app to expose the identity surface that
 * `crates/ferrogate-auth-service/src/server.rs` routes:
 *
 * | method              | path                            | guard                     |
 * |---------------------|---------------------------------|---------------------------|
 * | POST                | `/v1/admin/team/scim-token`     | admin session, owner only |
 * | GET, POST           | `/scim/v2/Users`                | `scim.provision` key      |
 * | GET,PATCH,PUT,DELETE| `/scim/v2/Users/:id`            | `scim.provision` key      |
 * | GET                 | `/scim/v2/Groups`               | `scim.provision` key      |
 * | GET                 | `/v1/admin/auth/sso/authorize`  | anonymous (by design)     |
 * | GET                 | `/v1/admin/auth/sso/callback`   | anonymous (by design)     |
 *
 * The two OIDC legs are anonymous BECAUSE the browser is not logged in yet —
 * that is the point of the flow. Their protection is the `state` (single-use,
 * expiring, unguessable) and the ID-token ladder, not a credential.
 *
 * NOT mounted here, deliberately: `POST|GET|DELETE /v1/admin/team/sso-config`.
 * That row is SHARED with the SAML provider kind, which lives in
 * `packages/sso`, so a single owner must mount it. The OIDC half of its
 * validation is exported as `validateOidcConfigInput` for that owner to call.
 *
 * ## Exact wiring for `apps/control-plane/src/index.ts` (integrate step owns it)
 *
 * ```ts
 * import { createIdentityRoutes } from "@ferrogate/identity";
 * // …after `app.use("*", contractAuth())` and BEFORE `registerRoutes(app)`:
 * export const IDENTITY_APP = createIdentityRoutes((c) => resolveIdentityDeps(c.env));
 * app.route("/", IDENTITY_APP);
 * ```
 *
 * MOUNT GATE (the assertion that makes the mount provable, for
 * `apps/control-plane/test/wiring.test.ts`):
 *
 * ```ts
 * import { IDENTITY_APP } from "../src/index.js";
 * test("the identity surface is mounted on the exported app", async () => {
 *   expect(IDENTITY_APP.identityRoutes.length).toBeGreaterThan(0);
 *   // and, on the REAL default export, not a bespoke app:
 *   const res = await SELF.fetch("https://cp.test/scim/v2/Users");
 *   expect(res.status).toBe(401);        // reached the SCIM guard
 *   expect(res.status).not.toBe(404);    // i.e. it is actually routed
 * });
 * ```
 *
 * The `404`-vs-`401` distinction is the whole gate: an unmounted sub-app
 * answers 404, and 404 is exactly what a "not implemented yet" surface also
 * answers, which is how an unmounted route survives a green suite.
 *
 * `/scim/v2/*` and `/v1/admin/*` are NOT among the 267 contract operations, so
 * mounting this app does not move the control plane's anti-drift count.
 */
import { Hono } from "hono";
import type { Context } from "hono";
import type { OidcDeps } from "./oidc/flow.js";
import { completeOidcCallback, startOidcAuthorize } from "./oidc/flow.js";
import type { IdentityResponse } from "./ports.js";
import { SCIM_PROVISION_SCOPE, bearerToken, resolveScimTenant } from "./scim/auth.js";
import type { ScimDeps, ScimUserRequest } from "./scim/service.js";
import {
  mintScimToken,
  scimGroupsList,
  scimUserCreate,
  scimUserDelete,
  scimUserGet,
  scimUserPatch,
  scimUsersList,
} from "./scim/service.js";

/** Everything both halves need. */
export type IdentityDeps = OidcDeps & ScimDeps;

/** One entry per `app.on(...)` the factory actually performed. */
export interface IdentityRouteRecord {
  method: string;
  path: string;
}

export interface IdentityRoutesApp extends Hono {
  /** The REAL registry of what was mounted, for the composition root's gate. */
  identityRoutes: readonly IdentityRouteRecord[];
}

/** Renders an `IdentityResponse` onto a Hono context. */
function render(c: Context, response: IdentityResponse): Response {
  if (response.status === 204 || response.body === null) {
    return c.body(null, response.status as 204);
  }
  const headers: Record<string, string> = {
    "content-type": response.scim ? "application/scim+json; charset=UTF-8" : "application/json",
  };
  return c.body(JSON.stringify(response.body), response.status as 200, headers);
}

/** Parses a JSON request body, or `undefined` when it is not JSON. */
async function readJsonBody(c: Context): Promise<unknown | undefined> {
  const raw = await c.req.text();
  if (raw.trim().length === 0) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function integerQuery(value: string | undefined): number | null {
  if (value === undefined || value.trim().length === 0) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Builds the identity sub-app over a per-request dependency resolver.
 *
 * `resolveDeps` is called once per request, so a composition root can build
 * its D1-backed repository from `c.env` exactly as it does for every other
 * route.
 */
export function createIdentityRoutes(resolveDeps: (c: Context) => IdentityDeps): IdentityRoutesApp {
  const app = new Hono() as IdentityRoutesApp;
  const routes: IdentityRouteRecord[] = [];

  const on = (
    method: string,
    path: string,
    handler: (c: Context) => Promise<Response> | Response,
  ) => {
    app.on(method, path, handler);
    routes.push({ method, path });
  };

  // ---------------------------------------------------------------------
  // THE SCIM GUARD. One `use` covering the whole `/scim/v2/*` prefix, so a
  // route added later is guarded by construction rather than by the author
  // remembering. It stashes the resolved tenant on the context; the handlers
  // below read it and have no other way to obtain a tenant.
  // ---------------------------------------------------------------------
  app.use("/scim/v2/*", async (c, next) => {
    const deps = resolveDeps(c);
    const resolution = await resolveScimTenant(deps, bearerToken(c.req.header("authorization")));
    if (!resolution.ok) return render(c, resolution.response);
    c.set("scimTenantId" as never, resolution.tenantId as never);
    c.set("identityDeps" as never, deps as never);
    await next();
  });

  const scimContext = (c: Context): { deps: ScimDeps; tenantId: string } => ({
    deps: c.get("identityDeps" as never) as unknown as ScimDeps,
    tenantId: c.get("scimTenantId" as never) as unknown as string,
  });

  on("GET", "/scim/v2/Users", async (c) => {
    const { deps, tenantId } = scimContext(c);
    return render(
      c,
      await scimUsersList(deps, tenantId, {
        filter: c.req.query("filter") ?? null,
        startIndex: integerQuery(c.req.query("startIndex")),
        count: integerQuery(c.req.query("count")),
      }),
    );
  });

  on("POST", "/scim/v2/Users", async (c) => {
    const { deps, tenantId } = scimContext(c);
    const body = await readJsonBody(c);
    if (body === undefined) {
      return render(c, {
        status: 400,
        scim: true,
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "400",
          detail: "request body is not valid JSON",
        },
      });
    }
    return render(c, await scimUserCreate(deps, tenantId, body as ScimUserRequest));
  });

  on("GET", "/scim/v2/Users/:id", async (c) => {
    const { deps, tenantId } = scimContext(c);
    return render(c, await scimUserGet(deps, tenantId, c.req.param("id") ?? ""));
  });

  // PATCH and PUT share the handler, exactly as `server.rs` routes them.
  for (const method of ["PATCH", "PUT"] as const) {
    on(method, "/scim/v2/Users/:id", async (c) => {
      const { deps, tenantId } = scimContext(c);
      const body = await readJsonBody(c);
      if (body === undefined) {
        return render(c, {
          status: 400,
          scim: true,
          body: {
            schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
            status: "400",
            detail: "request body is not valid JSON",
          },
        });
      }
      return render(c, await scimUserPatch(deps, tenantId, c.req.param("id") ?? "", body));
    });
  }

  on("DELETE", "/scim/v2/Users/:id", async (c) => {
    const { deps, tenantId } = scimContext(c);
    return render(c, await scimUserDelete(deps, tenantId, c.req.param("id") ?? ""));
  });

  on("GET", "/scim/v2/Groups", async (c) => {
    const { deps, tenantId } = scimContext(c);
    return render(
      c,
      await scimGroupsList(deps, tenantId, {
        filter: c.req.query("filter") ?? null,
        startIndex: integerQuery(c.req.query("startIndex")),
        count: integerQuery(c.req.query("count")),
      }),
    );
  });

  // --- the owner-gated SCIM credential mint ------------------------------
  on("POST", "/v1/admin/team/scim-token", async (c) =>
    render(c, await mintScimToken(resolveDeps(c), bearerToken(c.req.header("authorization")))),
  );

  // --- the two anonymous OIDC legs ---------------------------------------
  on("GET", "/v1/admin/auth/sso/authorize", async (c) => {
    const tenantId = c.req.query("tenant_id");
    if (!tenantId) {
      return render(c, {
        status: 422,
        body: {
          error: { type: "unprocessable_entity", message: "tenant_id query parameter is required" },
        },
      });
    }
    return render(c, await startOidcAuthorize(resolveDeps(c), tenantId));
  });

  on("GET", "/v1/admin/auth/sso/callback", async (c) => {
    const code = c.req.query("code");
    const state = c.req.query("state");
    if (!code || !state) {
      return render(c, {
        status: 422,
        body: {
          error: {
            type: "unprocessable_entity",
            message: "code and state query parameters are required",
          },
        },
      });
    }
    return render(c, await completeOidcCallback(resolveDeps(c), { code, state }));
  });

  app.identityRoutes = routes;
  return app;
}

export { SCIM_PROVISION_SCOPE };
