import { SELF } from "cloudflare:test";
/**
 * The anti-drift gate.
 *
 * `ROUTE-MAP.md`: "Add a test asserting every contract `operation_id` has a
 * handler — this is the anti-drift gate." Here that is scoped to the 15
 * operations this Worker owns: the table is loaded from the committed contract
 * JSON (there is no generated copy to drift from), and every operation is
 * PROBED over HTTP to prove a handler answers it.
 *
 * A probe that only asserted "not 404" would pass on a Worker that answered
 * everything with 401, so each probe asserts the operation's DECLARED auth
 * behaviour instead: bearer operations reject an anonymous caller with
 * `missing_api_key`, internal operations reject one with
 * `invalid_self_hosted_worker_transport_security`. That distinction can only
 * come from the contract table.
 */
import { describe, expect, it } from "vitest";
import {
  EXPECTED_INTERNAL_OPERATION_COUNT,
  EXPECTED_OWNED_OPERATION_COUNT,
  OPERATIONS,
  OWNED_OPERATION_IDS,
  allowedMethods,
  canonicalRequestPath,
  internalOperations,
  isOwnedPath,
  matchOperation,
  operationById,
  toHonoPath,
} from "../src/contract.js";
import { BASE, TENANT_A_KEY, bearer, getEnvVar, post, setEnvVar } from "./fixtures.js";

/** Substitute a concrete value for every `{param}` in a contract template. */
function concretePath(template: string): string {
  return template
    .replace("{run_id}", "job-00000000000000000000000000000000")
    .replace("{name}", "helper");
}

describe("contract table", () => {
  it("owns exactly the 15 operations ROUTE-MAP assigns", () => {
    expect(OPERATIONS).toHaveLength(EXPECTED_OWNED_OPERATION_COUNT);
    expect(OPERATIONS.map((operation) => operation.operationId).sort()).toEqual(
      [...OWNED_OPERATION_IDS].sort(),
    );
  });

  it("six of them are internal and nine are tenant bearer", () => {
    expect(internalOperations()).toHaveLength(EXPECTED_INTERNAL_OPERATION_COUNT);
    const bearerOps = OPERATIONS.filter((operation) => operation.auth.kind === "bearer");
    expect(bearerOps).toHaveLength(
      EXPECTED_OWNED_OPERATION_COUNT - EXPECTED_INTERNAL_OPERATION_COUNT,
    );
    // Every bearer operation names a scope; the contract parser rejects one
    // that does not, so this holds the invariant from the other side.
    expect(bearerOps.every((operation) => (operation.auth.scope ?? "") !== "")).toBe(true);
  });

  it("no owned operation is anonymous", () => {
    // ROUTE-MAP invariant 3: only /healthz, /readyz, /admin*, and
    // /.well-known/agent.json may be unauthenticated — none of which is ours.
    expect(OPERATIONS.some((operation) => operation.auth.kind === "anonymous")).toBe(false);
  });

  it("declares the scopes the Rust handlers enforced", () => {
    expect(operationById("submitAgentJob")?.auth.scope).toBe("agent.runs.create");
    // Starting and stopping tenant-billed work is the SAME privilege.
    expect(operationById("cancelAgentJob")?.auth.scope).toBe("agent.runs.create");
    expect(operationById("getAgentJob")?.auth.scope).toBe("agent.runs.read");
    expect(operationById("listAgentJobEvents")?.auth.scope).toBe("agent.runs.read");
    expect(operationById("getAgentJobResult")?.auth.scope).toBe("agent.runs.read");
    expect(operationById("createAgentRun")?.auth.scope).toBe("agents.invoke");
    expect(operationById("streamAgentMessage")?.auth.scope).toBe("agents.invoke");
  });

  it("resolves the static-vs-parameter conflict the way matchit does", () => {
    // `/v1/agent-jobs/{run_id}/events` and `/v1/agent-jobs/{run_id}` both match
    // a 4-segment path only if the matcher is wrong; the specific one wins.
    expect(matchOperation("GET", "/v1/agent-jobs/r1/events")?.operation.operationId).toBe(
      "listAgentJobEvents",
    );
    expect(matchOperation("GET", "/v1/agent-jobs/r1")?.operation.operationId).toBe("getAgentJob");
    expect(matchOperation("GET", "/v1/agent-jobs/r1")?.params.run_id).toBe("r1");
    // The A2A verb separator is a colon INSIDE a segment, not a new segment.
    expect(matchOperation("POST", "/v1/agents/helper/message:stream")?.operation.operationId).toBe(
      "streamAgentMessage",
    );
    expect(matchOperation("POST", "/v1/agents/helper")?.operation.operationId).toBe("invokeAgent");
  });

  it("normalizes the request path before matching", () => {
    expect(canonicalRequestPath("/v1/agent-jobs?limit=5")).toBe("/v1/agent-jobs");
    expect(canonicalRequestPath("/v1/agent-jobs/")).toBe("/v1/agent-jobs");
    expect(matchOperation("POST", "/v1/agent-jobs/")?.operation.operationId).toBe("submitAgentJob");
  });

  it("converts templates to Hono syntax", () => {
    expect(toHonoPath("/v1/agent-jobs/{run_id}/events")).toBe("/v1/agent-jobs/:run_id/events");
    expect(toHonoPath("/v1/self-hosted-workers/runs/poll")).toBe(
      "/v1/self-hosted-workers/runs/poll",
    );
  });

  it("knows which paths it owns", () => {
    expect(isOwnedPath("/v1/agent-jobs")).toBe(true);
    expect(isOwnedPath("/v1/self-hosted-workers/runs/ack")).toBe(true);
    expect(isOwnedPath("/v1/chat/completions")).toBe(false);
    expect(isOwnedPath("/admin/v1/agent-runs")).toBe(false);
  });

  it("reports the documented methods for a 405", () => {
    expect(allowedMethods("/v1/agent-jobs/r1")).toEqual(["GET"]);
    expect(allowedMethods("/v1/agent-runs")).toEqual(["POST"]);
  });
});

describe("every owned operation has a handler", () => {
  for (const operation of OPERATIONS) {
    it(`${operation.method} ${operation.path} (${operation.operationId})`, async () => {
      const response = await SELF.fetch(`${BASE}${concretePath(operation.path)}`, {
        method: operation.method,
        headers: { "content-type": "application/json" },
        body: operation.method === "GET" ? undefined : "{}",
      });
      const body = (await response.json()) as { error: { code: string } };

      if (operation.auth.kind === "internal") {
        // The worker-plane gate, not the tenant one — proof the table drove it.
        expect(response.status).toBe(401);
        expect(body.error.code).toBe("invalid_self_hosted_worker_transport_security");
      } else {
        expect(response.status).toBe(401);
        expect(body.error.code).toBe("missing_api_key");
      }
    });
  }
});

describe("routing refusals", () => {
  it("an undocumented method on an owned path is 405 with Allow", async () => {
    const response = await SELF.fetch(`${BASE}/v1/agent-runs`, { method: "GET" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "method_not_allowed",
    );
  });

  it("a path this Worker does not own is 404, even with a valid key", async () => {
    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: bearer(TENANT_A_KEY),
      body: "{}",
    });
    expect(response.status).toBe(404);
  });

  it("every error carries the uniform envelope and a request id", async () => {
    const response = await SELF.fetch(`${BASE}/v1/agent-jobs`, { method: "POST", body: "{}" });
    const body = (await response.json()) as {
      error: { message: string; type: string; code: string; request_id: string };
    };
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.request_id).toBeTruthy();
    expect(response.headers.get("x-request-id")).toBe(body.error.request_id);
  });

  it("an inbound x-request-id is honored so the caller can join on it", async () => {
    const response = await SELF.fetch(`${BASE}/v1/agent-jobs`, {
      method: "POST",
      headers: { "x-request-id": "req-from-caller" },
      body: "{}",
    });
    expect(response.headers.get("x-request-id")).toBe("req-from-caller");
  });

  it("the anonymous probes every Worker implements are reachable", async () => {
    for (const path of ["/healthz", "/readyz"]) {
      const response = await SELF.fetch(`${BASE}${path}`);
      expect(response.status, path).toBe(200);
      expect(await response.json()).toEqual({ ok: true });
    }
  });
});

describe("fail-closed when no ports are bound", () => {
  it("answers 503 rather than serving with a permissive stub", async () => {
    // A deploy that forgets to bind the real adapters must refuse, not default
    // to the in-memory dev bundle. The credential itself is valid here, so the
    // 503 can only come from the missing bindings.
    const original = getEnvVar("FG_DEV_IN_MEMORY_PORTS");
    setEnvVar("FG_DEV_IN_MEMORY_PORTS", undefined);
    try {
      const tenant = await post("/v1/agent-jobs", bearer(TENANT_A_KEY), { input: "x" });
      expect(tenant.status).toBe(503);
      expect(((await tenant.json()) as { error: { code: string } }).error.code).toBe(
        "agent_runtime_unavailable",
      );

      // The worker plane fails closed too: with no registry bound, no worker
      // identity can be validated, so nobody is admitted.
      const worker = await post(
        "/v1/self-hosted-workers/heartbeat",
        { "x-ferrogate-transport-security": "symmetric_aead", "content-type": "application/json" },
        { protocol_version: 1, identity: {}, status: "idle", reported_at_unix: 1 },
      );
      expect(worker.status).toBe(503);
    } finally {
      setEnvVar("FG_DEV_IN_MEMORY_PORTS", original);
    }
  });
});
