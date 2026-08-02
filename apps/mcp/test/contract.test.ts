/**
 * Anti-drift gate for `apps/mcp` (modelled on `apps/gateway/test/contract.test.ts`).
 *
 * `apps/gateway` shipped with an EMPTY module list in its composition root: 24
 * of its 31 contract operations were unreachable in the DEPLOYED Worker while
 * every suite stayed green, because each suite built its own router instead of
 * driving the app the Worker exports. This file exists so that cannot happen
 * here. It has three layers, and all three are required:
 *
 *  1. **Contract table** — the 6 operations ROUTE-MAP.md assigns to `apps/mcp`
 *     plus the 2 shared health operations, validated against the committed
 *     `docs/openapi/runtime-api-contract.json` (paths, methods, auth kinds,
 *     scopes, the `method_dependent` discriminator).
 *  2. **Registry** — every one of those 8 is registered on `mcpRouter`, the
 *     registry belonging to the app `src/index.ts` hands to `export default`.
 *     Deliberately NOT a bespoke `createMcpApp({ modules: [...] })` built here:
 *     a local module list is exactly how the gateway defect hid.
 *  3. **Reachability** — every one of those 8 is probed over `SELF.fetch`, i.e.
 *     the real `export default app` in real `workerd`, and asserted to answer
 *     the status/code only its OWN pipeline produces. A plain "not 404" would
 *     be too weak here: `/v1/mcp`, `/v1/mcp/tool/execute` and
 *     `/v1/mcp/identity/{server}` each carry a `405` method guard that would
 *     answer in an unmounted operation's place.
 *
 * Plus a 404 control probe, so "the app really does 404 a contracted path it
 * does not serve" is proven rather than assumed.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import contractDocument from "../../../docs/openapi/runtime-api-contract.json";

import { MCP_METHOD_SCOPES } from "../src/dispatch.js";
import { IDENTITY_OPERATION_IDS } from "../src/identity/routes.js";
import {
  ANONYMOUS_OPERATION_IDS,
  APP_OPERATION_IDS,
  EXPECTED_APP_OPERATION_COUNT,
  EXPECTED_OWNED_OPERATION_COUNT,
  MCP_ROUTE_MODULES,
  OPERATIONS,
  OWNED_OPERATION_IDS,
  PENDING_MODULE_OPERATION_IDS,
  SHARED_OPERATION_IDS,
  createMcpApp,
  mcpRouter,
  methodDependentScope,
  operationById,
  toHonoPath,
} from "../src/index.js";
import { INGRESS_OPERATION_IDS } from "../src/routes/ingress.js";
import { READ_KEY, seedFixture } from "./fixtures.js";

const BASE = "https://ferrogate.test";

interface RawOperation {
  path: string;
  method: string;
  operation_id: string;
}
const RAW_OPERATIONS = (contractDocument as unknown as { operations: RawOperation[] }).operations;

async function envelope(response: Response): Promise<{ code: string; message: string }> {
  const body = (await response.json()) as { error: { code: string; message: string } };
  return body.error;
}

// ---------------------------------------------------------------------------
// 1. Contract table
// ---------------------------------------------------------------------------

describe("contract slice", () => {
  it("serves exactly the 6 owned + 2 shared operations ROUTE-MAP assigns", () => {
    expect(OWNED_OPERATION_IDS).toHaveLength(EXPECTED_OWNED_OPERATION_COUNT);
    expect(SHARED_OPERATION_IDS).toHaveLength(2);
    expect(OPERATIONS).toHaveLength(EXPECTED_APP_OPERATION_COUNT);
    expect(new Set(OPERATIONS.map((operation) => operation.operationId))).toEqual(
      new Set(APP_OPERATION_IDS),
    );
  });

  it("owns EVERY /v1/mcp operation in the contract — no seventh may appear unclaimed", () => {
    // Read the whole 259-operation document, not this app's slice: if a
    // contract change adds a `/v1/mcp*` operation, ROUTE-MAP's split says it is
    // ours, and this fails until it is claimed and mounted.
    const mcpIds = RAW_OPERATIONS.filter(
      (operation) => operation.path === "/v1/mcp" || operation.path.startsWith("/v1/mcp/"),
    ).map((operation) => operation.operation_id);
    expect(new Set(mcpIds)).toEqual(new Set(OWNED_OPERATION_IDS));
  });

  it("carries the shared health operations every Worker must implement", () => {
    expect([...SHARED_OPERATION_IDS]).toEqual(["getHealthz", "getReadyz"]);
    expect(operationById("getHealthz")?.path).toBe("/healthz");
    expect(operationById("getHealthz")?.method).toBe("GET");
    expect(operationById("getReadyz")?.path).toBe("/readyz");
    expect(operationById("getReadyz")?.method).toBe("GET");
  });

  it("names exactly the 3 operations in this slice that may skip auth", () => {
    // ROUTE-MAP invariant 3. `/healthz` + `/readyz` are anonymous by contract,
    // and the OAuth callback is anonymous because the IdP redirects a browser
    // here with no FerroGate credential.
    const anonymous = OPERATIONS.filter((operation) => operation.auth.kind === "anonymous").map(
      (operation) => operation.operationId,
    );
    expect(new Set(anonymous)).toEqual(new Set(ANONYMOUS_OPERATION_IDS));
    expect(new Set(anonymous)).toEqual(
      new Set(["getHealthz", "getReadyz", "completeMcpIdentityOauth"]),
    );
  });

  it("keeps every bearer operation's declared scope", () => {
    expect(operationById("executeMcpTool")?.auth).toMatchObject({
      kind: "bearer",
      scope: "mcp.execute",
    });
    expect(operationById("getMcpIdentity")?.auth).toMatchObject({
      kind: "bearer",
      scope: "tools.read",
    });
    expect(operationById("revokeMcpIdentity")?.auth).toMatchObject({
      kind: "bearer",
      scope: "tools.execute",
    });
    expect(operationById("authorizeMcpIdentity")?.auth).toMatchObject({
      kind: "bearer",
      scope: "tools.execute",
    });
    // ...and no non-bearer operation smuggles a scope in.
    for (const operation of OPERATIONS) {
      if (operation.auth.kind === "bearer") continue;
      expect(operation.auth.scope, operation.operationId).toBeNull();
    }
  });

  it("resolves the ONE method_dependent scope from the contract discriminator", () => {
    // ROUTE-MAP invariant 4 — read the contract, never assume.
    const jsonRpc = operationById("mcpJsonRpc");
    expect(jsonRpc?.auth.kind).toBe("method_dependent");
    expect(jsonRpc?.auth.scopeDiscriminator?.field).toBe("method");
    expect(methodDependentScope("mcpJsonRpc", "tools/call")).toBe("tools.execute");
    expect(methodDependentScope("mcpJsonRpc", "tools/list")).toBe("tools.read");
    expect(methodDependentScope("mcpJsonRpc", "resources/read")).toBe("assets.read");
    expect(methodDependentScope("mcpJsonRpc", "tools/destroy")).toBeUndefined();
  });

  it("never lets an inherited Object key masquerade as a mapped scope", () => {
    for (const key of ["toString", "constructor", "__proto__", "hasOwnProperty"]) {
      expect(methodDependentScope("mcpJsonRpc", key), key).toBeUndefined();
      expect(MCP_METHOD_SCOPES.get(key), key).toBeUndefined();
    }
  });

  it("drives the dispatcher's method→scope table FROM the contract", () => {
    // `src/dispatch.ts` must not restate the map. If it ever does, this catches
    // the first divergence between the two.
    const fromContract = operationById("mcpJsonRpc")?.auth.scopeDiscriminator?.map;
    expect(fromContract).toBeDefined();
    expect([...MCP_METHOD_SCOPES.entries()].sort()).toEqual(
      [...(fromContract as ReadonlyMap<string, string>).entries()].sort(),
    );
  });

  it("translates contract templates to Hono syntax", () => {
    expect(toHonoPath("/v1/mcp/identity/{server}")).toBe("/v1/mcp/identity/:server");
    expect(toHonoPath("/v1/mcp/identity/{server}/authorize")).toBe(
      "/v1/mcp/identity/:server/authorize",
    );
    expect(toHonoPath("/healthz")).toBe("/healthz");
    // Every operation's `honoPath` is the translation of its contract path —
    // no route may be mounted at a hand-written path.
    for (const operation of OPERATIONS) {
      expect(operation.honoPath, operation.operationId).toBe(toHonoPath(operation.path));
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Registry — what the app the Worker EXPORTS actually mounted
// ---------------------------------------------------------------------------

describe("route registration", () => {
  // The PRODUCTION registry — the one belonging to the app `src/index.ts`
  // hands to `export default`.
  const registered = new Set(mcpRouter.registeredOperationIds());

  it("mounts ALL 8 operations on the app the Worker exports", () => {
    // THE gate. Nothing may be excused: every operation in this app's contract
    // slice is registered on the exported app.
    const missing = APP_OPERATION_IDS.filter((operationId) => !registered.has(operationId));
    expect(missing).toEqual([]);
    // ...and the registry is EXACTLY that set, so a stray registration is
    // caught in the same breath.
    expect(registered).toEqual(new Set(APP_OPERATION_IDS));
  });

  it("builds the production registry from the module list src/index.ts exports", () => {
    // The modules are the ones the composition root uses, not a copy.
    const fromModules = MCP_ROUTE_MODULES.flatMap((module) => module.operationIds);
    expect(new Set(fromModules)).toEqual(
      new Set([...INGRESS_OPERATION_IDS, ...IDENTITY_OPERATION_IDS]),
    );
    // A module list covering only some of the owned operations is the exact
    // shape of the gateway defect: the 6 owned ids must be fully covered.
    expect(new Set(fromModules)).toEqual(new Set(OWNED_OPERATION_IDS));
    // Every id a module claims is actually registered by that module.
    for (const operationId of fromModules) {
      expect(registered.has(operationId), operationId).toBe(true);
    }
  });

  it("registers the shared health operations", () => {
    for (const operationId of SHARED_OPERATION_IDS) {
      expect(registered.has(operationId), operationId).toBe(true);
    }
  });

  it("keeps the pending list honest — and it is EMPTY", () => {
    for (const operationId of PENDING_MODULE_OPERATION_IDS) {
      expect(OWNED_OPERATION_IDS).toContain(operationId);
      expect(registered.has(operationId), operationId).toBe(false);
    }
    expect(PENDING_MODULE_OPERATION_IDS).toEqual([]);
  });

  it("never registers a route that is not in the contract", () => {
    for (const operationId of mcpRouter.registeredOperationIds()) {
      expect(operationById(operationId), operationId).toBeDefined();
    }
  });

  it("refuses an operation id that is not in the contract", () => {
    const { router } = createMcpApp();
    expect(() => router.register("noSuchOperation", () => new Response())).toThrow(
      /not in the runtime API contract/,
    );
    // ...including a real contract operation owned by ANOTHER Worker.
    expect(() => router.register("createChatCompletion", () => new Response())).toThrow(
      /not in the runtime API contract/,
    );
  });

  it("refuses to register the same operation twice", () => {
    const { router } = createMcpApp();
    expect(() => router.register("getHealthz", () => new Response())).toThrow(/already registered/);
  });
});

// ---------------------------------------------------------------------------
// 3. Reachability on the DEPLOYED Worker
// ---------------------------------------------------------------------------

/**
 * One probe per contract operation. `expect` is the status + error code (or
 * `null` for a success body assertion made separately) that ONLY this
 * operation's own pipeline produces on the deployed app.
 *
 * Why not "not 404": three of these paths carry a `405` method guard, and
 * `/v1/mcp/identity/{server}` carries one that answers for BOTH the `GET` and
 * the `DELETE` operation. Unmounting either would still yield "not 404", so
 * each probe pins the code its handler alone returns.
 */
interface Probe {
  readonly operationId: string;
  readonly method: string;
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly status: number;
  /** Error-envelope `code` the handler returns; `null` for a 200 success. */
  readonly code: string | null;
}

const PROBES: readonly Probe[] = [
  // Shared: liveness / readiness answer 200 with their own body shape.
  { operationId: "getHealthz", method: "GET", path: "/healthz", status: 200, code: null },
  { operationId: "getReadyz", method: "GET", path: "/readyz", status: 200, code: null },
  // Ingress: reached WITHOUT a credential, so the handler's own auth step
  // answers 401 — a status the 405 method guard on this path never produces.
  {
    operationId: "mcpJsonRpc",
    method: "POST",
    path: "/v1/mcp",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    status: 401,
    code: "unauthenticated",
  },
  {
    operationId: "executeMcpTool",
    method: "POST",
    path: "/v1/mcp/tool/execute",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "srv-echo" }),
    status: 401,
    code: "unauthenticated",
  },
  // Identity: the callback is ANONYMOUS, so it runs past auth and answers its
  // own `mcp_oauth_callback_invalid` for a missing code/state. That also proves
  // `callback` was not captured as a `{server}` name.
  {
    operationId: "completeMcpIdentityOauth",
    method: "GET",
    path: "/v1/mcp/identity/callback",
    status: 400,
    code: "mcp_oauth_callback_invalid",
  },
  {
    operationId: "authorizeMcpIdentity",
    method: "POST",
    path: "/v1/mcp/identity/srv/authorize",
    status: 401,
    code: "unauthenticated",
  },
  {
    operationId: "getMcpIdentity",
    method: "GET",
    path: "/v1/mcp/identity/srv",
    status: 401,
    code: "unauthenticated",
  },
  {
    operationId: "revokeMcpIdentity",
    method: "DELETE",
    path: "/v1/mcp/identity/srv",
    status: 401,
    code: "unauthenticated",
  },
];

describe("the deployed Worker serves every operation it owns", () => {
  beforeEach(() => {
    seedFixture();
  });

  it("probes exactly this app's contract slice — no operation escapes the table", () => {
    expect(new Set(PROBES.map((probe) => probe.operationId))).toEqual(new Set(APP_OPERATION_IDS));
    // Each probe uses the operation's OWN contract method and path template, so
    // a contract move cannot leave the probe pointing at a stale URL.
    for (const probe of PROBES) {
      const operation = operationById(probe.operationId);
      expect(operation, probe.operationId).toBeDefined();
      expect(operation?.method, probe.operationId).toBe(probe.method);
      const template = (operation as { path: string }).path
        .replace("{server}", "srv")
        .replace(/\/$/, "");
      expect(probe.path, probe.operationId).toBe(template);
    }
  });

  it.each(PROBES.map((probe) => [probe.operationId, probe] as const))(
    "%s is reachable on SELF",
    async (operationId, probe) => {
      const res = await SELF.fetch(`${BASE}${probe.path}`, {
        method: probe.method,
        headers: probe.headers ?? {},
        ...(probe.body === undefined ? {} : { body: probe.body }),
      });
      expect(res.status, operationId).toBe(probe.status);
      if (probe.code !== null) {
        expect((await envelope(res)).code, operationId).toBe(probe.code);
      }
    },
  );

  it("answers /healthz and /readyz with this Worker's own identity", async () => {
    const healthz = await SELF.fetch(`${BASE}/healthz`);
    expect(healthz.status).toBe(200);
    // Rust `HealthResponse`, all four members in the struct's declaration order.
    // `protocol` is deliberately NOT here: it was an invention of this Worker,
    // and `/healthz` is a SHARED operation whose document must not depend on
    // which Worker answered. It stays on `/readyz` below, on `/version`, and in
    // the JSON-RPC `initialize` result, which is where a client reads it.
    expect(await healthz.json()).toEqual({
      status: "ok",
      service: "ferrogate-mcp",
      version: "0.0.0",
      runtime: "workers",
    });

    const readyz = await SELF.fetch(`${BASE}/readyz`);
    expect(readyz.status).toBe(200);
    expect(await readyz.json()).toEqual({
      status: "ready",
      service: "ferrogate-mcp",
      version: "0.0.0",
      runtime: "workers",
      protocol: "2026-07-28",
      // FC-1: readiness is now TWO conjuncts, and the probe reports both — the
      // dependency state AND the operator drain (`runtime-state/drain`). A
      // probe that answered `ready` on a drained deployment would send the load
      // balancer traffic every `tools/call` then refuses with 503.
      readiness_reason: "state_loaded",
      draining: false,
      accepting_new_requests: true,
      // The probe reports real dependency state, so it cannot claim readiness
      // on an isolate whose ports are unbound.
      dependencies: { ready: true },
    });
  });

  it("keeps the JSON-RPC leg fully live, not merely matched", async () => {
    // The reachability probes above stop at the 401; this one runs the whole
    // authenticated pipeline through the deployed app.
    const res = await SELF.fetch(`${BASE}/v1/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${READ_KEY}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result?: { tools?: unknown[] }; error?: unknown };
    expect(body.error).toBeUndefined();
    expect(body.result?.tools).toBeDefined();
  });

  it("still answers 404 for a contract path this Worker does not own", async () => {
    // The control for every probe above: `not 404` / a specific code is only a
    // mount proof because a contracted-but-unmounted path really does 404 here.
    for (const path of ["/v1/chat/completions", "/admin/v1/status", "/v1/assets"]) {
      // ...and each control path IS in the 259-operation contract, just not ours.
      expect(
        RAW_OPERATIONS.some((operation) => operation.path === path),
        path,
      ).toBe(true);
      expect(
        OPERATIONS.some((operation) => operation.path === path),
        path,
      ).toBe(false);

      const res = await SELF.fetch(`${BASE}${path}`, { method: "GET" });
      expect(res.status, path).toBe(404);
      expect((await envelope(res)).code, path).toBe("not_found");
    }
  });

  it("keeps the non-contract legacy probes working", async () => {
    // `/health` and `/version` predate the contract wiring and are NOT contract
    // operations — they must keep answering, and must stay out of the registry.
    expect(operationById("getHealth")).toBeUndefined();
    const health = await SELF.fetch(`${BASE}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    const version = await SELF.fetch(`${BASE}/version`);
    expect(version.status).toBe(200);
    expect((await version.json()) as { protocol: string }).toMatchObject({
      protocol: "2026-07-28",
    });
  });

  it("still guards the method on every fixed-method path", async () => {
    // The 405 guards are why the probes pin a code rather than "not 404".
    for (const [method, path] of [
      ["GET", "/v1/mcp"],
      ["GET", "/v1/mcp/tool/execute"],
      ["POST", "/v1/mcp/identity/callback"],
      ["PATCH", "/v1/mcp/identity/srv"],
    ] as const) {
      const res = await SELF.fetch(`${BASE}${path}`, { method });
      expect(res.status, `${method} ${path}`).toBe(405);
      expect((await envelope(res)).code, `${method} ${path}`).toBe("method_not_allowed");
    }
  });
});
