/**
 * ANTI-UNMOUNT: the tenancy middleware is in the chain of the app the Worker
 * exports, and it runs AFTER the auth guard.
 *
 * Everything here goes through `SELF.fetch`, i.e. the app
 * `harness/worker.ts` built from the REAL `createGatewayApp` + the REAL
 * `GATEWAY_ROUTE_MODULES`, with `middleware: [tenantDatabase()]` — the exact
 * zero-edit line documented for the integrate step in `src/tenancy/index.ts`.
 *
 * Deleting `tenantDatabase()` from that array turns this file red and leaves
 * every other spec in the suite green, which is the property being bought. That
 * mutation was run: with the middleware removed, `tenant_ghost` was served
 * `200 {"object":"list","data":[]}` from a Worker that had never resolved a
 * tenant database — precisely the silent shared-database posture this slice
 * exists to end.
 *
 * `harness/wrangler.toml` pins `GATEWAY_TENANT_DB_ROUTING = "binding_strict"`,
 * so a tenant-scoped credential must resolve BEFORE its request is served; that
 * is what makes the mount observable over HTTP rather than only at a store call.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import { GATEWAY_MIDDLEWARE, GATEWAY_ROUTE_MODULES } from "../../src/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { TENANT_DATABASE_UNAVAILABLE } from "../../src/tenancy/index.js";
import { setupTenancy } from "./setup.js";

const MODELS = "https://gw.tenancy.test/v1/models";

/**
 * The app the DEPLOYED composition root builds: the real `GATEWAY_ROUTE_MODULES`
 * and the real `GATEWAY_MIDDLEWARE`, nothing substituted. Built per case so no
 * memoized per-env state leaks between them.
 */
function deployedApp() {
  return createGatewayApp({
    modules: [...GATEWAY_ROUTE_MODULES],
    middleware: [...GATEWAY_MIDDLEWARE],
  }).app;
}

beforeAll(setupTenancy);

async function get(key?: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = {};
  if (key !== undefined) headers.authorization = `Bearer ${key}`;
  const response = await SELF.fetch(MODELS, { headers });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

/** The `error.code` of a gateway error envelope. */
function code(body: Record<string, unknown>): string | undefined {
  return (body.error as { code?: string } | undefined)?.code;
}

describe("tenantDatabase() is mounted on the deployed composition root", () => {
  test("a tenant WITH a provisioned, bound database is served", async () => {
    const acme = await get("fg_acme");
    expect(acme.status).toBe(200);
    expect(acme.body).toEqual({ object: "list", data: [] });

    // A second tenant, on a physically different database, is served too — so
    // the refusals below are about routability, not about the route being dead.
    const globex = await get("fg_globex");
    expect(globex.status).toBe(200);
  });

  test("an UNPROVISIONED tenant is refused, not served from the shared database", async () => {
    const ghost = await get("fg_ghost");
    expect(ghost.status).toBe(503);
    expect(code(ghost.body)).toBe(TENANT_DATABASE_UNAVAILABLE);
    // The 200 body a fallback would have produced must NOT be present.
    expect(ghost.body).not.toHaveProperty("data");
  });

  test("a tenant provisioned but not yet BOUND is refused", async () => {
    const unbound = await get("fg_unbound");
    expect(unbound.status).toBe(503);
    expect(code(unbound.body)).toBe(TENANT_DATABASE_UNAVAILABLE);
  });

  test("a registry row naming an undeployed binding is refused", async () => {
    const initech = await get("fg_initech");
    expect(initech.status).toBe(503);
    expect(code(initech.body)).toBe(TENANT_DATABASE_UNAVAILABLE);
  });

  test("the middleware runs AFTER the auth guard, not before it", async () => {
    // An anonymous caller must still get the auth guard's 401 — if the tenancy
    // middleware ran first it would have nothing to route on and would either
    // crash or mask the credential error.
    const anonymous = await get();
    expect(anonymous.status).toBe(401);
    expect(code(anonymous.body)).toBe("missing_api_key");

    // And an anonymous OPERATION (no auth at all) is untouched: `/healthz` has
    // `auth.kind: "anonymous"`, so nothing is resolved and nothing 503s.
    const health = await SELF.fetch("https://gw.tenancy.test/healthz");
    expect(health.status).toBe(200);
  });

  test("a platform-operator credential is served without a tenant database", async () => {
    // `CallerScope::PlatformOperator` is account-global by definition: there is
    // no single tenant whose database it should read, so eager resolution is
    // skipped rather than picking one (which would be a cross-tenant read).
    const root = await get("fg_root");
    expect(root.status).toBe(200);
    expect(root.body).toEqual({ object: "list", data: [] });
  });
});

/**
 * The PRODUCTION mount probe — flipped from `test.todo` by the wave-9 integrate
 * step, in the same commit that added `tenantDatabase()` to
 * `GATEWAY_MIDDLEWARE`.
 *
 * The suite above drives `harness/worker.ts`, which composes the REAL
 * `createGatewayApp` with `middleware: [tenantDatabase()]`. That proves the
 * middleware works in the chain — it does NOT prove the DEPLOYED array contains
 * it. This block closes exactly that gap: it imports `GATEWAY_MIDDLEWARE` from
 * `src/index.ts` (the composition root `src/worker.ts` re-exports).
 *
 * WHERE THE "delete the wiring line → red" PROPERTY NOW LIVES. It used to be
 * the unprovisioned-tenant refusal below: `binding_strict` made
 * `tenantDatabase()` resolve eagerly, so deleting it turned `fg_ghost`'s
 * `tenant_database_unavailable` into a silent shared-database 200. Track A
 * moved that. `residency()` is mounted immediately BEFORE `tenantDatabase()`
 * and, since `quota_policies` became per-tenant-object authoritative, it now
 * resolves the tenant through the SAME `resolverForEnv().forTenant()` the mount
 * uses (`src/tenancy/quota-policy-source.ts`) to seek the residency row. So an
 * unprovisioned tenant is refused by `residency()` FIRST — `503
 * residency_policy_unavailable`, still a refusal, still no shared-database serve
 * — and that refusal no longer depends on `tenantDatabase()` being in the array
 * at all. Asserting `tenant_database_unavailable` here would assert residency's
 * absence, not tenantDatabase's presence.
 *
 * The wiring fence therefore moves to the sibling "still serves a provisioned,
 * bound tenant" case: admission step 3b (`rateLimit()`'s wallet guard) calls
 * `tenantDatabaseOf(c)`, which throws `500` when the accessor was never mounted.
 * Deleting `tenantDatabase()` from `GATEWAY_MIDDLEWARE` turns `fg_acme` from
 * `200` into `500` there — the mutation was run and that is the case, and only
 * that case, that goes red. The refusal case below keeps the security invariant
 * it always asserted (an unprovisioned tenant is REFUSED, never served the `200
 * {"data":[]}` a shared-database fallback would produce), which the deployed
 * chain still upholds regardless of which tenant-object-dependent guard fronts.
 */
describe("the DEPLOYED composition root mounts tenantDatabase()", () => {
  test("GATEWAY_MIDDLEWARE refuses an unprovisioned tenant", async () => {
    const response = await deployedApp().request(
      MODELS,
      { headers: { authorization: "Bearer fg_ghost" } },
      env,
    );
    // Refused, not served from a shared database. Track A: `residency()` — the
    // tenant-object-dependent guard mounted just before `tenantDatabase()` —
    // fronts the refusal with `residency_policy_unavailable`; either way it is a
    // 503 with NO `data` body. The proof that `tenantDatabase()` specifically is
    // wired is the sibling case below, not the error code here.
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    // The 200 body a fallback would have produced must NOT be present.
    expect(body).not.toHaveProperty("data");
  });

  test("GATEWAY_MIDDLEWARE still serves a provisioned, bound tenant", async () => {
    // THE wiring fence (see the block comment): admission step 3b inside
    // `rateLimit()` calls `tenantDatabaseOf(c)`, which throws `500` when the
    // accessor was never mounted. Delete `tenantDatabase()` from
    // `GATEWAY_MIDDLEWARE` and this case goes `200 → 500`. It also guards the
    // inverse mistake — a wiring line that refused EVERYTHING would pass the
    // refusal case above while taking the gateway down.
    const response = await deployedApp().request(
      MODELS,
      { headers: { authorization: "Bearer fg_acme" } },
      env,
    );
    expect(response.status).toBe(200);
  });
});
