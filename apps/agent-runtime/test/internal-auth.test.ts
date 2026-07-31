/**
 * THE security invariant of this Worker (`ROUTE-MAP.md` invariant 2):
 *
 * > The 6 `/v1/self-hosted-workers/*` operations are worker-plane callbacks.
 * > They must NOT be reachable with a normal tenant bearer key.
 *
 * Every one of the six is asserted, individually, against a *valid, in-date,
 * fully-scoped* tenant key — the strongest tenant credential the fixture
 * offers, including the wildcard-scoped one. A test that only checked "no
 * credential ⇒ 401" would pass on a build where a tenant key WAS accepted,
 * which is the failure mode that matters.
 */
import { describe, expect, it } from "vitest";
import { internalOperations } from "../src/contract.js";
import {
  INTERNAL_ROUTES,
  TENANT_A_KEY,
  TENANT_A_SUSPENDED_KEY,
  WORKER_A,
  WORKER_B,
  bearer,
  post,
  workerHeaders,
} from "./fixtures.js";

/** A body that WOULD be valid if the caller were an authorized worker. */
function wellFormedBodyFor(path: string): Record<string, unknown> {
  const base = { protocol_version: 1, identity: WORKER_A };
  switch (path) {
    case "/v1/self-hosted-workers/heartbeat":
      return { ...base, status: "idle", reported_at_unix: 1_800_000_000 };
    case "/v1/self-hosted-workers/events":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        event_id: "e1",
        kind: "lifecycle",
        event_json: { state: "running" },
        reported_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/artifacts":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        artifact_id: "a1",
        name: "patch.diff",
        media_type: "text/x-diff",
        byte_len: 10,
        reported_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/checkpoints":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        checkpoint_id: "c1",
        created_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/runs/poll":
      return {
        ...base,
        supported_capabilities: [],
        now_unix: 1_800_000_000,
        lease_duration_secs: 60,
      };
    case "/v1/self-hosted-workers/runs/ack":
      return {
        ...base,
        dispatch_id: "d1",
        action: "start_run",
        lease_id: "l1",
        run_id: "r1",
        status: "completed",
        reported_at_unix: 1_800_000_000,
      };
    default:
      return base;
  }
}

describe("internal worker-plane callbacks reject tenant credentials", () => {
  it("the contract declares exactly 6 internal operations, none with a bearer scope", () => {
    const internal = internalOperations();
    expect(internal).toHaveLength(6);
    expect(internal.map((operation) => operation.path).sort()).toEqual([...INTERNAL_ROUTES].sort());
    // A scope here would mean a tenant bearer key could satisfy the operation.
    expect(internal.every((operation) => operation.auth.scope === null)).toBe(true);
    expect(internal.every((operation) => operation.visibility === "internal")).toBe(true);
  });

  for (const path of INTERNAL_ROUTES) {
    it(`${path} rejects a valid tenant bearer key`, async () => {
      const response = await post(path, bearer(TENANT_A_KEY), wellFormedBodyFor(path));
      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: { code: string } };
      // It fails at the FIRST worker-plane gate — the transport-security
      // marker — so the tenant credential is never even consulted.
      expect(body.error.code).toBe("invalid_self_hosted_worker_transport_security");
    });

    it(`${path} rejects a tenant bearer key even with the transport marker forged`, async () => {
      const response = await post(
        path,
        { ...bearer(TENANT_A_KEY), ...workerHeaders() },
        // The identity envelope is stripped: a tenant key grants no worker
        // identity, so this is exactly what a tenant caller could produce.
        { protocol_version: 1 },
      );
      expect(response.status).toBe(400);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe("invalid_self_hosted_worker_transport");
    });

    it(`${path} rejects a tenant bearer key presenting a guessed worker identity`, async () => {
      const body = wellFormedBodyFor(path);
      const response = await post(
        path,
        { ...bearer(TENANT_A_KEY), ...workerHeaders() },
        // Right worker id and tenancy, WRONG secret — the only thing a tenant
        // caller could not obtain.
        { ...body, identity: { ...WORKER_A, token_secret: `${"0".repeat(64)}` } },
      );
      expect(response.status).toBe(401);
      const parsed = (await response.json()) as { error: { code: string } };
      expect(parsed.error.code).toBe("invalid_self_hosted_worker_identity");
    });

    it(`${path} rejects an anonymous caller`, async () => {
      const response = await post(
        path,
        { "content-type": "application/json" },
        wellFormedBodyFor(path),
      );
      expect(response.status).toBe(401);
    });
  }

  it("a suspended tenant key is refused on internal routes too", async () => {
    const response = await post(
      "/v1/self-hosted-workers/heartbeat",
      bearer(TENANT_A_SUSPENDED_KEY),
      wellFormedBodyFor("/v1/self-hosted-workers/heartbeat"),
    );
    expect(response.status).toBe(401);
  });

  it("an unknown worker is 401 and a registered-but-inactive worker is 403", async () => {
    const unknown = await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
      protocol_version: 1,
      identity: { ...WORKER_A, worker_id: "worker-does-not-exist" },
      status: "idle",
      reported_at_unix: 1_800_000_000,
    });
    expect(unknown.status).toBe(401);
    expect(((await unknown.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_self_hosted_worker_identity",
    );

    const inactive = await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
      protocol_version: 1,
      identity: {
        tenant_id: "tenant-a",
        workspace_id: "ws-a",
        worker_id: "worker-a-retired",
        token_id: "tok-a-retired",
        token_secret: WORKER_A.token_secret,
      },
      status: "idle",
      reported_at_unix: 1_800_000_000,
    });
    expect(inactive.status).toBe(403);
    expect(((await inactive.json()) as { error: { code: string } }).error.code).toBe(
      "inactive_self_hosted_worker",
    );
  });

  it("a worker identity does NOT authenticate a tenant-bearer route", async () => {
    // The reverse direction of the same split: presenting a valid worker
    // envelope to a tenant route must not authenticate it.
    const response = await post("/v1/agent-jobs", workerHeaders(), {
      input: "x",
      identity: WORKER_A,
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "missing_api_key",
    );
  });

  it("an authorized worker IS admitted (the invariant is not vacuous)", async () => {
    // Without this, every assertion above would still pass on a build that
    // refused ALL callers — which is not the property being claimed.
    const response = await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      status: "idle",
      reported_at_unix: 1_800_000_000,
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { heartbeat: { worker_id: string; status: string } };
    expect(body.heartbeat.worker_id).toBe("worker-a");
    expect(body.heartbeat.status).toBe("idle");
  });

  it("worker B's credential cannot claim worker A's identity", async () => {
    const response = await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
      protocol_version: 1,
      identity: { ...WORKER_A, token_secret: WORKER_B.token_secret },
      status: "idle",
      reported_at_unix: 1_800_000_000,
    });
    expect(response.status).toBe(401);
  });

  it("an unsupported protocol_version is refused", async () => {
    const response = await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
      protocol_version: 99,
      identity: WORKER_A,
      status: "idle",
      reported_at_unix: 1_800_000_000,
    });
    expect(response.status).toBe(400);
  });

  it("a missing/unknown transport-security marker is refused before anything else", async () => {
    for (const security of [undefined, "plaintext"]) {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (security !== undefined) headers["x-ferrogate-transport-security"] = security;
      const response = await post("/v1/self-hosted-workers/heartbeat", headers, {
        protocol_version: 1,
        identity: WORKER_A,
        status: "idle",
        reported_at_unix: 1_800_000_000,
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        "invalid_self_hosted_worker_transport_security",
      );
    }
  });
});
