/**
 * Anti-drift gate (ROUTE-MAP.md "Porting guidance").
 *
 * The contract table is generated from the SAME JSON the Rust runtime consumed,
 * so a contract change cannot silently diverge from the implementation. These
 * assertions are the tripwire: shape of the table, the documented auth/
 * visibility/method census, the matcher's specificity rules, and the guarantee
 * that every gateway-owned operation is actually mounted.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { GATEWAY_ROUTE_MODULES, gatewayRouter } from "../src/index.js";
import {
  AUTH_KINDS,
  type AuthKind,
  EXPECTED_OPERATION_COUNT,
  type HttpMethod,
  OPERATIONS,
  type Visibility,
  canonicalizeAliasPath,
  matchOperation,
  matchRouteGroup,
  methodDependentScope,
  methodsForPath,
  operationById,
  operationIds,
  pathIsDocumented,
  toHonoPath,
} from "../src/contract.js";
import { hasScope } from "../src/ports.js";
import {
  ASSET_OPERATION_IDS,
  GATEWAY_OWNED_OPERATION_IDS,
  INFERENCE_OPERATION_IDS,
  OBSERVABILITY_OPERATION_IDS,
  PENDING_MODULE_OPERATION_IDS,
  SHARED_OPERATION_IDS,
  createGatewayApp,
} from "../src/routes/index.js";

function census<T extends string>(values: readonly T[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

describe("contract table", () => {
  it("carries exactly 261 operations", () => {
    expect(OPERATIONS).toHaveLength(EXPECTED_OPERATION_COUNT);
  });

  it("has 261 unique operation ids", () => {
    expect(new Set(operationIds()).size).toBe(EXPECTED_OPERATION_COUNT);
  });

  it("reproduces the documented auth-kind census", () => {
    // ROUTE-MAP.md: bearer 248 · internal 6 · anonymous 6 · method_dependent 1.
    // bearer went 238 -> 239 with `countMessageTokens` (issue #671), which is
    // bearer-`messages.create` like the `createMessage` it pre-flights,
    // 239 -> 242 with the three prompt-deployment-label operations (issue
    // #694), which are bearer-guarded like the rest of the prompt registry, and
    // 242 -> 248 with the six `/admin/v1/semantic-cache-policies/**` operations
    // (issue #695), which are `admin.read` / `admin.write` like every other
    // admin surface.
    expect(census(OPERATIONS.map<AuthKind>((operation) => operation.auth.kind))).toEqual({
      bearer: 248,
      internal: 6,
      anonymous: 6,
      method_dependent: 1,
    });
  });

  it("reproduces the documented visibility census", () => {
    expect(census(OPERATIONS.map<Visibility>((operation) => operation.visibility))).toEqual({
      // 193 -> 196 with the three prompt-deployment-label operations (issue
      // #694): prompt-registry management is admin-visibility; 196 -> 202 with
      // the six semantic-cache-policy operations (issue #695), likewise.
      admin: 202,
      // 51 -> 52 with `countMessageTokens` (issue #671): a data-plane
      // operation, publicly reachable, bearer-guarded.
      public: 52,
      internal: 7,
    });
  });

  it("reproduces the documented method census", () => {
    expect(census(OPERATIONS.map<HttpMethod>((operation) => operation.method))).toEqual({
      // GET/PUT/DELETE each +1 with the prompt-deployment-label operations
      // (issue #694): list/read, upsert, and delete of a label pointer; then
      // GET +2 / POST +2 / PUT +1 / DELETE +1 with the six semantic-cache-policy
      // operations (issue #695), whose POSTs are `create` and `invalidate`.
      GET: 119,
      // 78 -> 79 with `POST /v1/messages/count_tokens` (issue #671).
      POST: 81,
      DELETE: 26,
      PUT: 19,
      PATCH: 16,
    });
  });

  it("names exactly the 6 operations that may skip auth", () => {
    // ROUTE-MAP invariant 3 — nothing else may be unauthenticated.
    const anonymous = OPERATIONS.filter((operation) => operation.auth.kind === "anonymous").map(
      (operation) => operation.operationId,
    );
    expect(new Set(anonymous)).toEqual(
      new Set([
        "getHealthz",
        "getReadyz",
        "getAdminDashboard",
        "getAdminDashboardSlash",
        "getAdminDashboardAlias",
        "completeMcpIdentityOauth",
      ]),
    );
  });

  it("confines auth.kind: internal to the 6 self-hosted-worker callbacks", () => {
    // ROUTE-MAP invariant 2.
    const internal = OPERATIONS.filter((operation) => operation.auth.kind === "internal");
    expect(internal).toHaveLength(6);
    for (const operation of internal) {
      expect(operation.path.startsWith("/v1/self-hosted-workers/")).toBe(true);
    }
  });

  it("gives every bearer operation a scope", () => {
    for (const operation of OPERATIONS) {
      if (operation.auth.kind !== "bearer") continue;
      expect(operation.auth.scope, operation.operationId).toBeTruthy();
    }
    // ...and never a scope on any other kind.
    for (const operation of OPERATIONS) {
      if (operation.auth.kind === "bearer") continue;
      expect(operation.auth.scope, operation.operationId).toBeNull();
    }
  });

  it("keeps GET /metrics internal-but-bearer-guarded", () => {
    // ROUTE-MAP invariant 5.
    const metrics = matchOperation("GET", "/metrics")?.operation;
    expect(metrics?.visibility).toBe("internal");
    expect(metrics?.auth.kind).toBe("bearer");
  });

  it("only recognises the four documented auth kinds", () => {
    for (const operation of OPERATIONS) {
      expect(AUTH_KINDS).toContain(operation.auth.kind);
    }
  });
});

describe("lookup helpers", () => {
  it("resolves by operation id", () => {
    const operation = operationById("createChatCompletion");
    expect(operation?.method).toBe("POST");
    expect(operation?.path).toBe("/v1/chat/completions");
    expect(operation?.auth.scope).toBe("chat.completions");
  });

  it("returns undefined for an unknown operation id", () => {
    expect(operationById("noSuchOperation")).toBeUndefined();
  });

  it("resolves by (method, path) and captures path params", () => {
    const matched = matchOperation("GET", "/v1/assets/skill/hello/1.0.0");
    expect(matched?.operation.operationId).toBe("getAsset");
    expect(matched?.params).toEqual({ asset_type: "skill", name: "hello", version: "1.0.0" });
  });

  it("is method-sensitive on a shared path", () => {
    expect(matchOperation("PUT", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "putAsset",
    );
    expect(matchOperation("DELETE", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "deleteAsset",
    );
  });

  it("prefers a static segment over a parameter (matchit specificity)", () => {
    // `/v1/assets/withheld` must win over `/v1/assets/{asset_type}`.
    expect(matchOperation("GET", "/v1/assets/withheld")?.operation.operationId).toBe(
      "listWithheldAssets",
    );
    expect(matchOperation("GET", "/v1/assets/skill")?.operation.operationId).toBe(
      "listAssetsByType",
    );
    // ...and at a deeper position too.
    expect(matchOperation("GET", "/v1/assets/skill/hello/manifest")?.operation.operationId).toBe(
      "getAssetManifest",
    );
    expect(matchOperation("GET", "/v1/assets/skill/hello/channels")?.operation.operationId).toBe(
      "listAssetChannels",
    );
    expect(matchOperation("GET", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "getAsset",
    );
  });

  it("distinguishes /admin from /admin/", () => {
    expect(matchOperation("GET", "/admin")?.operation.operationId).toBe("getAdminDashboard");
    expect(matchOperation("GET", "/admin/")?.operation.operationId).toBe("getAdminDashboardSlash");
  });

  it("reports documented paths and their methods", () => {
    expect(pathIsDocumented("/v1/tools")).toBe(true);
    expect(pathIsDocumented("/v1/definitely/not/a/route")).toBe(false);
    expect(methodsForPath("/v1/tools")).toEqual(["GET"]);
    expect(new Set(methodsForPath("/v1/assets/skill/hello/1.0.0"))).toEqual(
      new Set(["GET", "PUT", "DELETE"]),
    );
  });

  it("maps every path to a route group", () => {
    for (const operation of OPERATIONS) {
      expect(operation.group, operation.operationId).toBeTruthy();
    }
    expect(matchRouteGroup("/v1/chat/completions")).toBe("inference");
    expect(matchRouteGroup("/healthz")).toBe("health");
  });

  it("resolves the method_dependent scope from the contract discriminator", () => {
    // ROUTE-MAP invariant 4 — read the contract, never assume.
    expect(methodDependentScope("POST", "/v1/mcp", "tools/call")).toBe("tools.execute");
    expect(methodDependentScope("POST", "/v1/mcp", "tools/list")).toBe("tools.read");
    expect(methodDependentScope("POST", "/v1/mcp", "resources/read")).toBe("assets.read");
    // An unmapped value yields no scope — callers must treat that as a denial.
    expect(methodDependentScope("POST", "/v1/mcp", "tools/destroy")).toBeUndefined();
    // ...including inherited Object keys, which must not leak through.
    expect(methodDependentScope("POST", "/v1/mcp", "toString")).toBeUndefined();
  });

  it("translates contract templates to Hono syntax", () => {
    expect(toHonoPath("/v1/assets/{asset_type}/{name}/{version}")).toBe(
      "/v1/assets/:asset_type/:name/:version",
    );
    expect(toHonoPath("/v1/agent-jobs/{*rest}")).toBe("/v1/agent-jobs/*");
    expect(toHonoPath("/healthz")).toBe("/healthz");
  });

  it("canonicalizes the /control/v1 alias onto /admin/v1", () => {
    // ROUTE-MAP invariant 7.
    expect(canonicalizeAliasPath("/control/v1/status")).toBe("/admin/v1/status");
    expect(canonicalizeAliasPath("/control/v1")).toBe("/admin/v1");
    expect(canonicalizeAliasPath("/control/v1x/status")).toBeNull();
    expect(canonicalizeAliasPath("/admin/v1/status")).toBeNull();
  });
});

describe("scope semantics", () => {
  it("grants an exact or wildcard scope", () => {
    expect(hasScope(["tools.read"], "tools.read")).toBe(true);
    expect(hasScope(["*"], "admin.write")).toBe(true);
  });

  it("denies a scope the key does not hold", () => {
    expect(hasScope(["skills.read"], "tools.read")).toBe(false);
  });

  it("lets an EMPTY scope set reach data-plane scopes but never admin.*", () => {
    // The durable/virtual-key asymmetry: no scopes must not become admin.
    expect(hasScope([], "tools.read")).toBe(true);
    expect(hasScope([], "admin.read")).toBe(false);
    expect(hasScope([], "admin.write")).toBe(false);
  });
});

describe("route registration", () => {
  // The PRODUCTION router — the one `src/index.ts` hands to `export default`.
  // Deliberately NOT a bespoke `createGatewayApp({ modules: [...] })` built
  // here: a local module list is exactly how the deployed Worker came to mount
  // 7 of its 32 operations while this suite stayed green.
  const router = gatewayRouter;
  const registered = new Set(router.registeredOperationIds());

  it("owns exactly the 32 operations ROUTE-MAP assigns to apps/gateway", () => {
    // 31 -> 32 with `countMessageTokens` (issue #671).
    expect(GATEWAY_OWNED_OPERATION_IDS).toHaveLength(32);
    for (const operationId of GATEWAY_OWNED_OPERATION_IDS) {
      expect(operationById(operationId), operationId).toBeDefined();
    }
  });

  it("registers every gateway-owned operation that is not pending another agent", () => {
    const missing = GATEWAY_OWNED_OPERATION_IDS.filter(
      (operationId) =>
        !registered.has(operationId) && !PENDING_MODULE_OPERATION_IDS.includes(operationId),
    );
    expect(missing).toEqual([]);
  });

  it("mounts ALL 32 gateway-owned operations on the app the Worker exports", () => {
    // THE gate. Nothing may be excused by a pending list: every operation
    // ROUTE-MAP assigns to apps/gateway is registered on the exported app.
    const missing = GATEWAY_OWNED_OPERATION_IDS.filter(
      (operationId) => !registered.has(operationId),
    );
    expect(missing).toEqual([]);
    // ...and the registry is exactly the 32 owned + the 2 shared health ops +
    // `getMetrics`, so a stray registration is caught in the same breath.
    //
    // `getMetrics` is deliberately its OWN list rather than a 32nd owned
    // operation or a third "shared" one. ROUTE-MAP assigns the operation to
    // `apps/control-plane`; the cutover certification found that leaving it
    // ONLY there means the 47 `ferrogate_*` series a dashboard queries have no
    // producer, because the counters live in this Worker. Mounting it here is
    // an addition with a reason, and this line is where that reason has to be
    // re-stated if anyone ever adds another.
    expect(new Set(registered)).toEqual(
      new Set([
        ...SHARED_OPERATION_IDS,
        ...OBSERVABILITY_OPERATION_IDS,
        ...GATEWAY_OWNED_OPERATION_IDS,
      ]),
    );
  });

  it("does not smuggle getMetrics into the OWNED or SHARED lists", () => {
    // The exact-set assertion above would still pass if `getMetrics` were
    // quietly appended to either list, and the distinction is the whole
    // argument: `SHARED_OPERATION_IDS` means "every Worker implements this",
    // and `apps/mcp` / `apps/telemetry` do not.
    expect(GATEWAY_OWNED_OPERATION_IDS).not.toContain("getMetrics");
    expect([...SHARED_OPERATION_IDS]).not.toContain("getMetrics");
    expect([...OBSERVABILITY_OPERATION_IDS]).toEqual(["getMetrics"]);
  });

  it("builds the production registry from the module list src/index.ts exports", () => {
    // The modules are the ones the composition root uses, not a copy.
    const fromModules = GATEWAY_ROUTE_MODULES.flatMap((module) => module.operationIds);
    expect(new Set(fromModules)).toEqual(
      new Set([...INFERENCE_OPERATION_IDS, ...ASSET_OPERATION_IDS]),
    );
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

  it("never registers a route that is not in the contract", () => {
    for (const operationId of router.registeredOperationIds()) {
      expect(operationById(operationId), operationId).toBeDefined();
    }
  });

  it("keeps the pending list honest — and it is now EMPTY", () => {
    // Every pending id is gateway-owned...
    for (const operationId of PENDING_MODULE_OPERATION_IDS) {
      expect(GATEWAY_OWNED_OPERATION_IDS).toContain(operationId);
      // ...and is NOT already mounted (otherwise the list is stale).
      expect(registered.has(operationId), operationId).toBe(false);
    }
    // Nothing is outstanding: the inference and asset modules are both wired
    // into `src/index.ts`, so no gateway-owned operation may be excused.
    expect(PENDING_MODULE_OPERATION_IDS).toEqual([]);
  });

  it("refuses an operation id that is not in the contract", () => {
    const { router: fresh } = createGatewayApp();
    expect(() => fresh.register("noSuchOperation", () => new Response())).toThrow(
      /not in the runtime API contract/,
    );
  });

  it("refuses to register the same operation twice", () => {
    const { router: fresh } = createGatewayApp();
    expect(() => fresh.register("getHealthz", () => new Response())).toThrow(/already registered/);
  });
});

/**
 * The registry assertions above prove `src/index.ts` REGISTERED the 24 module
 * operations. These prove the deployed Worker actually SERVES them: every
 * request below goes through `SELF.fetch`, i.e. the real `export default app`
 * in real `workerd`, with a credential that clears the contract guard. A
 * contract path that is guarded but not mounted answers `404 not_found` from
 * `gatewayNotFoundHandler` — so "not 404" is the mount proof, and the exact
 * status/code asserted alongside it proves the module's own pipeline ran.
 */
const BASE = "https://ferrogate.test";
/** Operator-authored static key with no scope list => every scope. */
const ROOT = { authorization: "Bearer fg_root" } as const;

async function envelope(response: Response): Promise<{ code: string; message: string }> {
  const body = (await response.json()) as { error: { code: string; message: string } };
  return body.error;
}

describe("the deployed Worker serves the mounted modules", () => {
  it("mounts the 7 inference operations", async () => {
    // GET /v1/models reaches the inference handler: an empty catalog, not a 404.
    const models = await SELF.fetch(`${BASE}/v1/models`, { headers: ROOT });
    expect(models.status).toBe(200);
    expect(await models.json()).toEqual({ object: "list", data: [] });

    // Every POST reaches the inner body-reader + Zod chain: an empty object is
    // the module's own `400 invalid_request`, which only that chain produces.
    const posts = [
      "/v1/chat/completions",
      "/v1/responses",
      "/v1/messages",
      // `count_tokens` shares the Messages schema, so `{}` is the same
      // `invalid_request` (issue #671).
      "/v1/messages/count_tokens",
      "/v1/embeddings",
      "/v1/images/generations",
    ];
    for (const path of posts) {
      const res = await SELF.fetch(`${BASE}${path}`, {
        method: "POST",
        headers: { ...ROOT, "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status, path).toBe(400);
      expect((await envelope(res)).code, path).toBe("invalid_request");
    }

    // ...and the reader's `invalid_json` stays distinct from `invalid_request`,
    // which is the behavior a plain Zod validator would have lost.
    const malformed = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { ...ROOT, "content-type": "application/json" },
      body: "{not json",
    });
    expect(malformed.status).toBe(400);
    expect((await envelope(malformed)).code).toBe("invalid_json");
  });

  it("mounts the 18 /v1/assets/** operations", async () => {
    // Reach EVERY asset operation at its contract path with its contract
    // method. `fg_root` has no tenant attribution, so the asset service — which
    // only runs once the route is mounted — answers `403 tenant_required`.
    const probes: readonly (readonly [string, string, string])[] = [
      ["listAssets", "GET", "/v1/assets"],
      ["getAssetStorageSummary", "GET", "/v1/assets/storage/summary"],
      ["listWithheldAssets", "GET", "/v1/assets/withheld"],
      ["listAssetsByType", "GET", "/v1/assets/skill"],
      ["getAsset", "GET", "/v1/assets/skill/hello/1.0.0"],
      ["putAsset", "PUT", "/v1/assets/skill/hello/1.0.0"],
      ["deleteAsset", "DELETE", "/v1/assets/skill/hello/1.0.0"],
      ["getAssetManifest", "GET", "/v1/assets/skill/hello/manifest"],
      ["listAssetChannels", "GET", "/v1/assets/skill/hello/channels"],
      ["putAssetChannel", "PUT", "/v1/assets/skill/hello/channels/stable?version=1.0.0"],
      ["deleteAssetChannel", "DELETE", "/v1/assets/skill/hello/channels/stable"],
      ["yankAssetVersion", "POST", "/v1/assets/skill/hello/1.0.0/yank"],
      ["unyankAssetVersion", "DELETE", "/v1/assets/skill/hello/1.0.0/yank"],
      ["promoteAssetVisibility", "POST", "/v1/assets/skill/hello/1.0.0/visibility"],
      ["createAssetUploadIntent", "POST", "/v1/assets/presign/upload/skill/hello/1.0.0"],
      ["commitAssetUpload", "POST", "/v1/assets/presign/commit/skill/hello/1.0.0"],
      ["abortAssetUpload", "POST", "/v1/assets/presign/abort/skill/hello/1.0.0"],
      ["getAssetDownloadUrl", "GET", "/v1/assets/presign/download/skill/hello/1.0.0"],
    ];
    // The probe table is the contract's asset set, so a renamed operation
    // cannot quietly drop out of this test.
    expect(new Set(probes.map(([operationId]) => operationId))).toEqual(
      new Set(ASSET_OPERATION_IDS),
    );

    for (const [operationId, method, path] of probes) {
      const operation = operationById(operationId);
      expect(operation?.method, operationId).toBe(method);
      const res = await SELF.fetch(`${BASE}${path}`, {
        method,
        headers: { ...ROOT, "content-type": "application/json" },
        ...(method === "POST" || method === "PUT" ? { body: "{}" } : {}),
      });
      // The mount proof: never the app's "no route" answer.
      expect(res.status, `${operationId} ${method} ${path}`).not.toBe(404);
      const { code } = await envelope(res);
      expect(code, `${operationId} ${method} ${path}`).not.toBe("not_found");
    }
  });

  it("still answers 404 for a contract path this Worker does not own", async () => {
    // The control for the two tests above: `not 404` is only a mount proof
    // because a contracted-but-unmounted path, reached with a credential that
    // clears the guard, really does answer 404 here.
    const unowned = operationById("getAdminStatus");
    expect(unowned?.path).toBe("/admin/v1/status");
    expect(GATEWAY_OWNED_OPERATION_IDS).not.toContain("getAdminStatus");

    const res = await SELF.fetch(`${BASE}/admin/v1/status`, { headers: ROOT });
    expect(res.status).toBe(404);
    expect((await envelope(res)).code).toBe("not_found");
  });
});
