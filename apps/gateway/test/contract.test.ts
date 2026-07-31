/**
 * Anti-drift gate (ROUTE-MAP.md "Porting guidance").
 *
 * The contract table is generated from the SAME JSON the Rust runtime consumed,
 * so a contract change cannot silently diverge from the implementation. These
 * assertions are the tripwire: shape of the table, the documented auth/
 * visibility/method census, the matcher's specificity rules, and the guarantee
 * that every gateway-owned operation is actually mounted.
 */
import { describe, expect, it } from "vitest";
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
  it("carries exactly 251 operations", () => {
    expect(OPERATIONS).toHaveLength(EXPECTED_OPERATION_COUNT);
  });

  it("has 251 unique operation ids", () => {
    expect(new Set(operationIds()).size).toBe(EXPECTED_OPERATION_COUNT);
  });

  it("reproduces the documented auth-kind census", () => {
    // ROUTE-MAP.md: bearer 238 · internal 6 · anonymous 6 · method_dependent 1.
    expect(census(OPERATIONS.map<AuthKind>((operation) => operation.auth.kind))).toEqual({
      bearer: 238,
      internal: 6,
      anonymous: 6,
      method_dependent: 1,
    });
  });

  it("reproduces the documented visibility census", () => {
    expect(census(OPERATIONS.map<Visibility>((operation) => operation.visibility))).toEqual({
      admin: 193,
      public: 51,
      internal: 7,
    });
  });

  it("reproduces the documented method census", () => {
    expect(census(OPERATIONS.map<HttpMethod>((operation) => operation.method))).toEqual({
      GET: 116,
      POST: 78,
      DELETE: 24,
      PUT: 17,
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
  const { router } = createGatewayApp();
  const registered = new Set(router.registeredOperationIds());

  it("owns exactly the 31 operations ROUTE-MAP assigns to apps/gateway", () => {
    expect(GATEWAY_OWNED_OPERATION_IDS).toHaveLength(31);
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

  it("keeps the pending list honest", () => {
    // Every pending id is gateway-owned...
    for (const operationId of PENDING_MODULE_OPERATION_IDS) {
      expect(GATEWAY_OWNED_OPERATION_IDS).toContain(operationId);
      // ...and is NOT already mounted (otherwise the list is stale).
      expect(registered.has(operationId), operationId).toBe(false);
    }
    expect(new Set(PENDING_MODULE_OPERATION_IDS)).toEqual(
      new Set([...INFERENCE_OPERATION_IDS, ...ASSET_OPERATION_IDS]),
    );
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

// The inference (6) and asset (18) modules are owned by other agents this wave.
// When they land they are appended to `modules` in src/index.ts and removed from
// PENDING_MODULE_OPERATION_IDS, which tightens the assertion above automatically.
it.todo("mounts the 6 inference operations (inference agent)");
it.todo("mounts the 18 /v1/assets/** operations (assets agent)");
