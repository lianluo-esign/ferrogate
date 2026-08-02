/**
 * Anti-drift gate for the composition root.
 *
 * The failure this guards against is concrete: an app can declare a surface and
 * ship a Worker that mounts none of it, while every suite passes because each
 * one builds its own router. So these assertions run against the DEFAULT EXPORT
 * of `src/index.ts` — the object `wrangler deploy` uploads — and against
 * `SELF`, the same module booted in `workerd`.
 *
 * The two shared operations are additionally checked against
 * `docs/openapi/runtime-api-contract.json`, the authoritative contract: path,
 * method and `auth.kind: "anonymous"` come from the JSON, not from this file.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import contract from "../../../docs/openapi/runtime-api-contract.json" with { type: "json" };
import app, { OTLP_ROUTES, SHARED_OPERATION_IDS, TELEMETRY_ROUTES } from "../src/index.js";
import { authHeaders, logsPayload, metricsPayload, tracesPayload } from "./fixtures.js";

interface ContractOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: { kind: string; scope: string | null };
}

const OPERATIONS = (contract as { operations: ContractOperation[] }).operations;

function operationById(id: string): ContractOperation {
  const found = OPERATIONS.find((op) => op.operation_id === id);
  if (!found) throw new Error(`contract has no operation ${id}`);
  return found;
}

describe("the deployed app mounts every declared route", () => {
  it("registers each entry of TELEMETRY_ROUTES on the exported app", () => {
    const mounted = new Set(app.routes.map((route) => `${route.method} ${route.path}`));
    for (const route of TELEMETRY_ROUTES) {
      expect(mounted, `${route.method} ${route.path} is not mounted`).toContain(
        `${route.method} ${route.path}`,
      );
    }
  });

  it("declares all three OTLP signal paths", () => {
    const declared = TELEMETRY_ROUTES.filter((route) => route.path.startsWith("/v1/")).map(
      (route) => route.path,
    );
    expect(new Set(declared)).toEqual(new Set(Object.keys(OTLP_ROUTES)));
    expect(Object.keys(OTLP_ROUTES)).toEqual(["/v1/metrics", "/v1/traces", "/v1/logs"]);
  });

  it("serves every declared route through SELF (never 404)", async () => {
    const bodies: Record<string, unknown> = {
      "/v1/metrics": metricsPayload(),
      "/v1/traces": tracesPayload(),
      "/v1/logs": logsPayload(),
    };
    for (const route of TELEMETRY_ROUTES) {
      const body = bodies[route.path];
      const res = await SELF.fetch(`https://ferrogate.test${route.path}`, {
        method: route.method,
        ...(route.method === "POST" ? { headers: authHeaders(), body: JSON.stringify(body) } : {}),
      });
      expect(res.status, `${route.method} ${route.path}`).not.toBe(404);
      expect(res.status, `${route.method} ${route.path}`).toBeLessThan(500);
    }
  });

  it("enforces the declared auth on every route through SELF", async () => {
    for (const route of TELEMETRY_ROUTES) {
      const res = await SELF.fetch(`https://ferrogate.test${route.path}`, {
        method: route.method,
        ...(route.method === "POST"
          ? { headers: { "content-type": "application/json" }, body: "{}" }
          : {}),
      });
      if (route.anonymous) {
        expect(res.status, `${route.path} must not require a credential`).not.toBe(401);
      } else {
        expect(res.status, `${route.path} must require a credential`).toBe(401);
      }
    }
  });
});

describe("the shared contract operations", () => {
  it("declares exactly getHealthz + getReadyz as shared", () => {
    expect([...SHARED_OPERATION_IDS]).toEqual(["getHealthz", "getReadyz"]);
  });

  it.each([...SHARED_OPERATION_IDS])(
    "%s is mounted at the contract's own path/method, anonymously",
    (operationId) => {
      const operation = operationById(operationId);
      const declared = TELEMETRY_ROUTES.find((route) => route.operationId === operationId);
      expect(declared, `${operationId} is not in TELEMETRY_ROUTES`).toBeDefined();
      expect(declared?.path).toBe(operation.path);
      expect(declared?.method).toBe(operation.method.toUpperCase());
      // The contract says anonymous; ROUTE-MAP invariant 3 says only these
      // (plus the admin/agent surfaces) may be unauthenticated.
      expect(operation.auth.kind).toBe("anonymous");
      expect(declared?.anonymous).toBe(true);
      expect(app.routes.map((route) => `${route.method} ${route.path}`)).toContain(
        `${operation.method.toUpperCase()} ${operation.path}`,
      );
    },
  );

  it("owns no OTHER contract operation — telemetry is the sink, not a surface", () => {
    const contractPaths = new Set(OPERATIONS.map((op) => op.path));
    const mountedContractPaths = TELEMETRY_ROUTES.filter((route) =>
      contractPaths.has(route.path),
    ).map((route) => route.path);
    expect(new Set(mountedContractPaths)).toEqual(new Set(["/healthz", "/readyz"]));
  });
});
