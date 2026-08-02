import { SELF, env } from "cloudflare:test";
/**
 * The anti-drift gate.
 *
 * `ROUTE-MAP.md`: "Add a test asserting every contract `operation_id` has a
 * handler — this is the anti-drift gate." Here that is scoped to the 15
 * operations this Worker owns: the table is loaded from the committed contract
 * JSON (there is no generated copy to drift from), and every operation is
 * PROBED over HTTP — through `SELF`, i.e. against the module `src/index.ts`
 * DEFAULT-EXPORTS and `wrangler.toml` names as `main`, never against a router a
 * test built for itself.
 *
 * ## Why there are TWO probe passes
 *
 * The obvious probe — "call it anonymously, expect the declared refusal" — is
 * NOT a reachability test, and believing it was is the composition-root defect
 * that shipped in `apps/gateway`. `contractAuth` refuses BEFORE `next()`, so an
 * anonymous request to an operation whose handler module was never
 * `app.route()`-ed still returns the same 401. Deleting a whole module from the
 * composition root leaves that pass entirely green. Proven by mutation, not
 * assumed.
 *
 * So:
 *
 *  1. **auth-dispatch pass** (anonymous) — proves the CONTRACT TABLE drove the
 *     guard: bearer operations answer `missing_api_key`, internal operations
 *     answer `invalid_self_hosted_worker_transport_security`. Only the table can
 *     produce that split.
 *  2. **reachability pass** (authenticated) — proves a HANDLER IS MOUNTED:
 *     each operation is called with the credential its contract entry demands
 *     and must produce a handler-originated response. An unmounted module falls
 *     through to `notFoundHandler`, whose code is the reserved `not_found` — the
 *     discriminator every probe asserts against, with a control probe below
 *     proving `not_found` is actually observable through this harness.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  EXPECTED_INTERNAL_OPERATION_COUNT,
  EXPECTED_OWNED_OPERATION_COUNT,
  OPERATIONS,
  OWNED_OPERATION_IDS,
  type OwnedOperationId,
  allowedMethods,
  canonicalRequestPath,
  internalOperations,
  isOwnedPath,
  matchOperation,
  operationById,
  toHonoPath,
} from "../src/contract.js";
import {
  BASE,
  TENANT_A_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  getEnvVar,
  pollLease,
  post,
  setEnvVar,
  submitJob,
  workerEnvelopeFor,
  workerHeaders,
} from "./fixtures.js";

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

describe("pass 1 — the contract table drives the guard on every owned operation", () => {
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

// ---------------------------------------------------------------------------
// Pass 2 — reachability on the PRODUCTION app
// ---------------------------------------------------------------------------

/**
 * `notFoundHandler`'s code. A response carrying it means Hono matched NO route
 * and fell through — i.e. the handler module is not mounted on the exported
 * app. No handler in this Worker ever originates it: the run/job handlers use
 * `agent_job_not_found` and the A2A handler uses `agent_not_found`, precisely so
 * a handler-originated miss stays distinguishable from a routing miss.
 */
const UNMOUNTED_CODE = "not_found";

interface ReachabilityProbe {
  /** The request the probe ultimately makes — asserted to match the contract. */
  readonly method: string;
  readonly path: string;
  /** Drive the operation with the credential its contract entry demands. */
  readonly run: () => Promise<Response>;
  /** Statuses a MOUNTED handler may answer with. Never includes a routing 404. */
  readonly expectStatus: readonly number[];
  /** The `object` discriminator of a 2xx body, when there is one. */
  readonly expectObject?: string;
  /** The `error.code` of a deliberate non-2xx handler answer. */
  readonly expectErrorCode?: string;
}

/**
 * One probe per owned operation, keyed by `operation_id`.
 *
 * Typed as a total `Record<OwnedOperationId, …>`, so ADDING an operation to
 * `OWNED_OPERATION_IDS` without adding a reachability probe is a TYPE error,
 * not a silently smaller test run.
 */
const REACHABILITY_PROBES: Record<OwnedOperationId, ReachabilityProbe> = {
  createAgentRun: {
    method: "POST",
    path: "/v1/agent-runs",
    run: () => post("/v1/agent-runs", bearer(TENANT_A_KEY), { input: "reachability probe" }),
    expectStatus: [200, 202],
    expectObject: "agent_run",
  },
  submitAgentJob: {
    method: "POST",
    path: "/v1/agent-jobs",
    run: () => post("/v1/agent-jobs", bearer(TENANT_A_KEY), { input: "reachability probe" }),
    expectStatus: [200, 202],
    expectObject: "agent_job",
  },
  getAgentJob: {
    method: "GET",
    path: "/v1/agent-jobs/{run_id}",
    run: async () => {
      const { runId } = await submitJob(TENANT_A_KEY);
      return await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    },
    expectStatus: [200],
    expectObject: "agent_job",
  },
  listAgentJobEvents: {
    method: "GET",
    path: "/v1/agent-jobs/{run_id}/events",
    run: async () => {
      const { runId } = await submitJob(TENANT_A_KEY);
      return await get(`/v1/agent-jobs/${runId}/events`, bearer(TENANT_A_KEY));
    },
    expectStatus: [200],
    // Rust `agent_jobs.rs:838`; was `"list"` (cutover finding D7.1) until
    // wave 17.
    expectObject: "agent_job_event_page",
  },
  getAgentJobResult: {
    method: "GET",
    path: "/v1/agent-jobs/{run_id}/result",
    run: async () => {
      const { runId } = await submitJob(TENANT_A_KEY);
      return await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    },
    // A freshly queued run is not terminal — a refusal only the RESULT handler
    // can produce, so it proves reachability as firmly as a 200 would.
    expectStatus: [409],
    expectErrorCode: "agent_job_not_terminal",
  },
  cancelAgentJob: {
    method: "POST",
    path: "/v1/agent-jobs/{run_id}/cancel",
    run: async () => {
      const { runId } = await submitJob(TENANT_A_KEY);
      return await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    },
    expectStatus: [200],
    expectObject: "agent_job_cancel",
  },
  invokeAgent: {
    method: "POST",
    path: "/v1/agents/{name}",
    run: () => post("/v1/agents/helper", bearer(TENANT_A_KEY), { parts: [{ text: "hi" }] }),
    // Egress is sealed by default (#471); the refusal is raised by the A2A
    // handler's governance leg, which only runs if that handler was reached.
    expectStatus: [422],
    expectErrorCode: "egress_host_not_governed",
  },
  sendAgentMessage: {
    method: "POST",
    path: "/v1/agents/{name}/message:send",
    run: () =>
      post("/v1/agents/helper/message:send", bearer(TENANT_A_KEY), { parts: [{ text: "hi" }] }),
    expectStatus: [422],
    expectErrorCode: "egress_host_not_governed",
  },
  streamAgentMessage: {
    method: "POST",
    path: "/v1/agents/{name}/message:stream",
    run: () =>
      post("/v1/agents/helper/message:stream", bearer(TENANT_A_KEY), { parts: [{ text: "hi" }] }),
    expectStatus: [422],
    expectErrorCode: "egress_host_not_governed",
  },
  recordSelfHostedWorkerHeartbeat: {
    method: "POST",
    path: "/v1/self-hosted-workers/heartbeat",
    run: () =>
      post(
        "/v1/self-hosted-workers/heartbeat",
        workerHeaders(),
        workerEnvelopeFor("/v1/self-hosted-workers/heartbeat"),
      ),
    expectStatus: [201],
    expectObject: "self_hosted_worker_heartbeat",
  },
  recordSelfHostedWorkerEvent: {
    method: "POST",
    path: "/v1/self-hosted-workers/events",
    run: () =>
      post(
        "/v1/self-hosted-workers/events",
        workerHeaders(),
        workerEnvelopeFor("/v1/self-hosted-workers/events"),
      ),
    expectStatus: [201],
    expectObject: "self_hosted_worker_event",
  },
  uploadSelfHostedWorkerArtifact: {
    method: "POST",
    path: "/v1/self-hosted-workers/artifacts",
    run: () =>
      post(
        "/v1/self-hosted-workers/artifacts",
        workerHeaders(),
        workerEnvelopeFor("/v1/self-hosted-workers/artifacts"),
      ),
    expectStatus: [201],
    expectObject: "self_hosted_worker_artifact",
  },
  uploadSelfHostedWorkerCheckpoint: {
    method: "POST",
    path: "/v1/self-hosted-workers/checkpoints",
    run: () =>
      post(
        "/v1/self-hosted-workers/checkpoints",
        workerHeaders(),
        workerEnvelopeFor("/v1/self-hosted-workers/checkpoints"),
      ),
    expectStatus: [201],
    expectObject: "self_hosted_worker_checkpoint",
  },
  pollSelfHostedWorkerRun: {
    method: "POST",
    path: "/v1/self-hosted-workers/runs/poll",
    run: async () => {
      // Enqueue real work first, so a 200-with-lease (not the ambiguous 204) is
      // what proves the handler ran.
      await submitJob(TENANT_A_KEY);
      return await post("/v1/self-hosted-workers/runs/poll", workerHeaders(), {
        protocol_version: 1,
        identity: WORKER_A,
        supported_capabilities: ["coding"],
        now_unix: 1_800_000_000,
        lease_duration_secs: 300,
      });
    },
    expectStatus: [200],
    expectObject: "self_hosted_run_lease",
  },
  acknowledgeSelfHostedWorkerRun: {
    method: "POST",
    path: "/v1/self-hosted-workers/runs/ack",
    run: async () => {
      // A REAL lease, so the ack is accepted rather than refused — a refusal
      // would also be handler-originated, but only a settled ack proves the
      // whole callback body ran.
      await submitJob(TENANT_A_KEY);
      const lease = await pollLease(WORKER_A);
      expect(lease, "the poll probe must lease work for the ack probe").not.toBeNull();
      return await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
        protocol_version: 1,
        identity: WORKER_A,
        dispatch_id: lease?.dispatch_id,
        action: lease?.action,
        lease_id: lease?.lease_id,
        run_id: lease?.run_id,
        status: "completed",
        reported_at_unix: 1_800_000_100,
      });
    },
    expectStatus: [200],
    expectObject: "self_hosted_run_ack",
  },
};

describe("pass 2 — every owned operation is REACHABLE on the exported app", () => {
  beforeEach(async () => {
    await drainPlane(WORKER_A);
  });

  it("every owned operation has a probe (no operation can be skipped)", () => {
    expect(Object.keys(REACHABILITY_PROBES).sort()).toEqual([...OWNED_OPERATION_IDS].sort());
    expect(Object.keys(REACHABILITY_PROBES)).toHaveLength(EXPECTED_OWNED_OPERATION_COUNT);
  });

  for (const operation of OPERATIONS) {
    const probe = REACHABILITY_PROBES[operation.operationId as OwnedOperationId];

    it(`${operation.method} ${operation.path} (${operation.operationId})`, async () => {
      // The probe addresses THIS operation and not a neighbouring one — without
      // this, a copy-pasted probe could prove the wrong route is mounted.
      expect(probe.method).toBe(operation.method);
      expect(probe.path).toBe(operation.path);
      expect(matchOperation(probe.method, concretePath(probe.path))?.operation.operationId).toBe(
        operation.operationId,
      );

      const response = await probe.run();
      const text = await response.text();
      const body = text === "" ? {} : (JSON.parse(text) as Record<string, unknown>);
      const error = body.error as { code?: string } | undefined;

      // THE reachability assertion: falling through to `notFoundHandler` is
      // exactly what an unmounted handler module looks like from outside.
      expect(
        error?.code,
        `${operation.operationId} fell through to notFound — its handler is not mounted on the exported app`,
      ).not.toBe(UNMOUNTED_CODE);
      expect(response.status, `${operation.operationId} -> ${text}`).toBeOneOf([
        ...probe.expectStatus,
      ]);
      if (probe.expectObject !== undefined) expect(body.object).toBe(probe.expectObject);
      if (probe.expectErrorCode !== undefined) expect(error?.code).toBe(probe.expectErrorCode);
    });
  }

  it("CONTROL: an unmounted path under an owned prefix DOES report not_found", async () => {
    // Without this the reachability assertion above could be trivially true
    // (e.g. if `not_found` were unreachable through this harness). These paths
    // sit inside the Worker's own prefixes and are authenticated exactly like
    // their neighbours, so the only reason they miss is that nothing serves them.
    const control = [
      await get(`${"/v1/agent-jobs"}/job-1/not-an-operation`, bearer(TENANT_A_KEY)),
      await post("/v1/self-hosted-workers/not-an-operation", workerHeaders(), {
        protocol_version: 1,
        identity: WORKER_A,
      }),
      await post("/v1/agents/helper/message:teleport", bearer(TENANT_A_KEY), {}),
    ];
    for (const response of control) {
      expect(response.status).toBe(404);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        UNMOUNTED_CODE,
      );
    }
  });
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
    // Wave 17 (cutover certification ops 53 + 54): these two used to answer a
    // flat `{ok:true}` — "a different document entirely" from gateway/mcp, and
    // a `/readyz` that could never answer 503. They now serve the shared
    // contract documents out of `src/routes/health.ts`; the full decision table
    // is in `test/routes/health-contract.test.ts`. Asserted here too so the
    // contract suite cannot go green on a Worker that regressed to `{ok:true}`.
    for (const path of ["/healthz", "/readyz"]) {
      const response = await SELF.fetch(`${BASE}${path}`);
      expect(response.status, path).toBe(200);
      const body = (await response.json()) as Record<string, unknown>;
      expect(body, path).not.toEqual({ ok: true });
      expect(body.service, path).toBe("ferrogate-agent-runtime");
      expect(body.runtime, path).toBe("workers");
      expect(body.version, path).toBe("0.0.0");
    }
    expect(await (await SELF.fetch(`${BASE}/healthz`)).json()).toMatchObject({ status: "ok" });
    expect(await (await SELF.fetch(`${BASE}/readyz`)).json()).toMatchObject({
      status: "ready",
      ready: true,
      readiness_reason: "state_loaded",
    });
    // `/health` is the one probe no client contract describes; it stays terse.
    expect(await (await SELF.fetch(`${BASE}/health`)).json()).toEqual({ ok: true });
  });
});

describe("wrangler bindings match what src/ actually exports", () => {
  it("both Durable Object classes named in wrangler.toml are exported by the entry module", async () => {
    // Wrangler resolves `class_name` against the ENTRY MODULE's exports, so a
    // class that moved or was renamed inside src/ is a deploy-time failure with
    // no compile-time signal. Naming them here makes that a test failure.
    const entry = (await import("../src/index.js")) as Record<string, unknown>;
    expect(typeof entry.AgentRunState, "AgentRunState (binding AGENT_RUN_STATE)").toBe("function");
    expect(typeof entry.WorkerPlane, "WorkerPlane (binding WORKER_PLANE)").toBe("function");
    expect(entry.default).toBeDefined();
  });

  it("both Durable Object namespaces are really bound and addressable", async () => {
    // Proof the `[[durable_objects.bindings]]` + `[[migrations]]` pair is
    // coherent: an id can be derived and a stub obtained for each. A missing
    // migration or a class-name typo fails here rather than on first traffic.
    for (const namespace of [env.AGENT_RUN_STATE, env.WORKER_PLANE]) {
      expect(namespace).toBeDefined();
      const stub = namespace.get(namespace.idFromName("binding-probe"));
      expect(stub).toBeDefined();
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
