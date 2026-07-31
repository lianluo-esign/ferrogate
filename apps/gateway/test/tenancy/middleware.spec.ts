/**
 * `tenantDatabase()` + `tenantDatabaseOf()` semantics, against REAL D1.
 *
 * `mount.spec.ts` proves the middleware is in the deployed chain; this file
 * proves what it does once it is there — lazy vs eager resolution, the
 * platform-operator case, and the refusal a handler gets when the middleware
 * was never mounted at all.
 *
 * The apps here are small on purpose: they exist to reach `tenantDatabaseOf(c)`
 * from a handler, which no contract operation does yet. They do NOT stand in
 * for the composition-root assertions — those are in `mount.spec.ts` and go
 * through `SELF`.
 */
import { env } from "cloudflare:test";
import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import { beforeAll, describe, expect, test } from "vitest";
import { gatewayErrorHandler, requestId } from "../../src/middleware/errors.js";
import type { AuthContext, GatewayEnv } from "../../src/ports.js";
import {
  TENANT_DATABASE_UNAVAILABLE,
  TENANT_DATABASE_UNSCOPED,
  type TenancyBindings,
  routableTenantId,
  tenantDatabase,
  tenantDatabaseOf,
} from "../../src/tenancy/index.js";
import { TENANT_ACME, TENANT_GHOST, TENANT_GLOBEX, setupTenancy, walletFor } from "./setup.js";

beforeAll(setupTenancy);

function authContext(tenantId: string | null, platformOperator = false): AuthContext {
  return {
    subject: "key_probe",
    tenancy: { tenantId },
    scopes: ["*"],
    platformOperator,
    source: "durable_native",
  };
}

/** `contractAuth` stand-in: parks a resolved credential exactly as it does. */
function withAuth(auth: AuthContext | null): MiddlewareHandler<GatewayEnv> {
  return async (c, next) => {
    c.set("auth", auth);
    await next();
  };
}

/**
 * A probe app: request id → auth → the REAL `tenantDatabase()` → a handler that
 * asks for the tenant handle. `mountTenancy: false` omits the middleware, which
 * is what proves `tenantDatabaseOf` refuses rather than reaching for `env.DB`.
 */
function probeApp(
  auth: AuthContext | null,
  options: { mountTenancy?: boolean; routing?: string } = {},
) {
  const app = new Hono<GatewayEnv>();
  app.onError(gatewayErrorHandler);
  app.use("*", requestId);
  app.use("*", withAuth(auth));
  if (options.mountTenancy !== false) app.use("*", tenantDatabase());
  app.get("/probe", async (c) => {
    const handle = await tenantDatabaseOf(c).handle();
    const row = await handle.db
      .prepare("SELECT tenant_id, balance_credits FROM wallets WHERE tenant_id = ?")
      .bind(handle.tenantId)
      .first<{ balance_credits: number }>();
    return c.json({
      tenantId: handle.tenantId,
      source: handle.source,
      supportsAtomicBatch: handle.supportsAtomicBatch,
      balance: row?.balance_credits ?? null,
    });
  });
  // A route that never asks for a tenant database — used to prove laziness.
  app.get("/untouched", (c) => c.json({ ok: true, mode: tenantDatabaseOf(c).mode }));

  const bindings = {
    ...(env as unknown as TenancyBindings),
    ...(options.routing === undefined ? {} : { GATEWAY_TENANT_DB_ROUTING: options.routing }),
  };
  return (path: string) => app.request(`https://probe.test${path}`, {}, bindings);
}

describe("the accessor hands a handler ITS OWN tenant's database", () => {
  beforeAll(async () => {
    await env.TENANT_DB_ACME.prepare(
      "INSERT OR REPLACE INTO wallets (id, tenant_id, balance_credits, dunning, " +
        "created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
    )
      .bind(TENANT_ACME, TENANT_ACME, 777, 1, 1)
      .run();
    const globex = walletFor(TENANT_GLOBEX, 3);
    await env.TENANT_DB_GLOBEX.prepare(
      "INSERT OR REPLACE INTO wallets (id, tenant_id, balance_credits, dunning, " +
        "created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
    )
      .bind(globex.id, globex.tenantId, globex.balanceCredits, 1, 1)
      .run();
  });

  test("two credentials on the same route read two different databases", async () => {
    const acme = await (await probeApp(authContext(TENANT_ACME))("/probe")).json();
    const globex = await (await probeApp(authContext(TENANT_GLOBEX))("/probe")).json();

    expect(acme).toEqual({
      tenantId: TENANT_ACME,
      source: "native_binding",
      supportsAtomicBatch: true,
      balance: 777,
    });
    // The same SQL, the same handler, a different physical database.
    expect(globex).toEqual({
      tenantId: TENANT_GLOBEX,
      source: "native_binding",
      supportsAtomicBatch: true,
      balance: 3,
    });
  });

  test("an unresolvable tenant is a 503 refusal, not the shared database", async () => {
    const response = await probeApp(authContext(TENANT_GHOST))("/probe");
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe(TENANT_DATABASE_UNAVAILABLE);
  });

  test("a platform-operator credential has no tenant database, and is told so", async () => {
    const response = await probeApp(authContext(null, true))("/probe");
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe(TENANT_DATABASE_UNSCOPED);
    // …but a route that does not ask is unaffected.
    expect((await probeApp(authContext(null, true))("/untouched")).status).toBe(200);
  });

  test("routableTenantId follows Rust CallerScope, never promoting to root", () => {
    expect(routableTenantId(authContext(TENANT_ACME))).toBe(TENANT_ACME);
    expect(routableTenantId(authContext(null, true))).toBeNull();
    // An unclassified credential is a TENANT with the unforgeable empty id —
    // it can match no `tenant_databases` row, so it routes nowhere.
    expect(routableTenantId(authContext(null))).toBe("");
  });
});

describe("lazy by default, eager under binding_strict", () => {
  test('"binding" does not resolve for a route that never asks', async () => {
    // `tenant_ghost` has no registry row at all. Under lazy routing a route
    // that never asks for the handle must still be served — the cost of a
    // control-database read belongs to the call sites that need it.
    const response = await probeApp(authContext(TENANT_GHOST), { routing: "binding" })(
      "/untouched",
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, mode: "binding" });
  });

  test('"binding_strict" refuses the SAME request before the handler runs', async () => {
    const response = await probeApp(authContext(TENANT_GHOST), { routing: "binding_strict" })(
      "/untouched",
    );
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe(TENANT_DATABASE_UNAVAILABLE);
  });

  test("an anonymous request attaches nothing at all", async () => {
    // No credential ⇒ nothing to route on. The accessor is absent, and asking
    // for it is the programming error `tenantDatabaseOf` names.
    const response = await probeApp(null)("/untouched");
    expect(response.status).toBe(500);
  });
});

describe("tenantDatabaseOf refuses when the middleware is not mounted", () => {
  test("an unmounted gateway 500s instead of silently using the shared DB", async () => {
    const response = await probeApp(authContext(TENANT_ACME), { mountTenancy: false })("/probe");
    // The alternative — returning `c.env.DB` — is exactly the defect this
    // directory exists to prevent, and it would have answered 200 with
    // tenant_acme's balance read out of whatever database happened to be bound.
    expect(response.status).toBe(500);
  });
});
