/**
 * `/readyz` — the ported `handle_readyz` + `ClusterStatus::new` decision table,
 * and the pinned APPROXIMATION of the one input the platform constrains
 * (operator drain is deploy-time here, not a runtime `AtomicBool`; see the
 * PORT-TODO in `src/routes/readiness.ts`).
 */
import { describe, expect, it } from "vitest";

import {
  activeRevisionFor,
  clusterStatus,
  drainStatus,
} from "../../src/routes/readiness.js";
import { createGatewayApp } from "../../src/routes/index.js";

interface ReadyBody {
  status: string;
  service: string;
  runtime: string;
  cluster: {
    ready: boolean;
    readiness_reason: string;
    draining: boolean;
    accepting_new_requests: boolean;
    active_revision: string;
    enabled: boolean;
    stale: boolean;
    last_sync_error: string | null;
  };
}

function readyz(env: Record<string, string> = {}): Promise<Response> {
  const { app } = createGatewayApp();
  return Promise.resolve(app.request("https://gw.test/readyz", {}, env));
}

describe("GET /readyz", () => {
  it("is 200 ready with a config revision loaded and no drain", async () => {
    const res = await readyz({ GATEWAY_PROVIDERS: "[]" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as ReadyBody;
    expect(body.status).toBe("ready");
    expect(body.service).toBe("ferrogate-gateway");
    expect(body.cluster.ready).toBe(true);
    expect(body.cluster.readiness_reason).toBe("state_loaded");
    expect(body.cluster.accepting_new_requests).toBe(true);
    expect(body.cluster.active_revision).toMatch(/^[0-9a-f]{16}$/);
  });

  it("answers 503 not_ready while the deployment is drained", async () => {
    const res = await readyz({ GATEWAY_DRAIN: "true" });
    // The whole point of the port: a drained node is REFUSED by the load
    // balancer, not reported healthy. 200 here would be the regression.
    expect(res.status).toBe(503);
    const body = (await res.json()) as ReadyBody;
    expect(body.status).toBe("not_ready");
    expect(body.cluster.ready).toBe(false);
    expect(body.cluster.draining).toBe(true);
    expect(body.cluster.accepting_new_requests).toBe(false);
    expect(body.cluster.readiness_reason).toBe("operator_drain");
  });

  it("only the exact string `true` drains", async () => {
    for (const value of ["false", "1", "yes", "", "  "]) {
      expect((await readyz({ GATEWAY_DRAIN: value })).status).toBe(200);
    }
    // …case-insensitively, and ignoring surrounding whitespace.
    for (const value of ["TRUE", " true "]) {
      expect((await readyz({ GATEWAY_DRAIN: value })).status).toBe(503);
    }
  });

  it("stays anonymous — readiness must not require a credential", async () => {
    expect((await readyz()).status).toBe(200);
  });

  it("reports a revision that changes with the config and is stable for it", async () => {
    const first = ((await (await readyz({ GATEWAY_MODELS: "[]" })).json()) as ReadyBody).cluster;
    const same = ((await (await readyz({ GATEWAY_MODELS: "[]" })).json()) as ReadyBody).cluster;
    const other = ((await (
      await readyz({ GATEWAY_MODELS: '[{"name":"m"}]' })
    ).json()) as ReadyBody).cluster;
    expect(first.active_revision).toBe(same.active_revision);
    expect(first.active_revision).not.toBe(other.active_revision);
  });
});

describe("ClusterStatus::new decision table", () => {
  it("names each arm exactly as the Rust does", () => {
    expect(clusterStatus({ activeRevision: "abc", draining: false })).toMatchObject({
      ready: true,
      readiness_reason: "state_loaded",
    });
    expect(clusterStatus({ activeRevision: "abc", draining: true })).toMatchObject({
      ready: false,
      readiness_reason: "operator_drain",
    });
    expect(
      clusterStatus({ activeRevision: "abc", draining: false, stale: true }),
    ).toMatchObject({ ready: true, readiness_reason: "stale_state" });
    expect(
      clusterStatus({ activeRevision: "", draining: false, lastSyncError: "boom" }),
    ).toMatchObject({ ready: false, readiness_reason: "sync_error" });
    expect(clusterStatus({ activeRevision: "", draining: false })).toMatchObject({
      ready: false,
      readiness_reason: "revision_missing",
    });
    // Whitespace is not a revision (`active_revision.trim().is_empty()`).
    expect(clusterStatus({ activeRevision: "   ", draining: false }).ready).toBe(false);
  });

  it("drain wins over a loaded revision", () => {
    expect(clusterStatus({ activeRevision: "abc", draining: true }).ready).toBe(false);
  });

  it("an UNEVALUABLE drain is drain_state_unavailable, NOT operator_drain", () => {
    // FC-1, wave 22. The gateway's drain is now the durable
    // `runtime-state/drain` document OR the var, and a control database that is
    // BOUND and FAILS is a third state. Refusing is non-negotiable — a probe
    // that reports ready when its control could not be evaluated is the bypass
    // again — but naming a drain nobody performed, while `GET /admin/v1/drain`
    // says the fleet is not draining, is the incident-time lie
    // `routes/drain.ts::drainRefusal` splits into two codes on the data plane.
    // `apps/mcp` and `apps/agent-runtime` answer identically; the boot proof
    // caught both of them collapsing it.
    const unavailable = clusterStatus({
      activeRevision: "abc",
      draining: false,
      drainUnavailable: true,
    });
    expect(unavailable.ready).toBe(false);
    expect(unavailable.readiness_reason).toBe("drain_state_unavailable");
    expect(unavailable.readiness_reason).not.toBe("operator_drain");
    // NOT draining — the operator drained nothing.
    expect(unavailable.draining).toBe(false);
    // Still refusing: this field must agree with `ready`, or one document tells
    // a load balancer and an operator opposite things.
    expect(unavailable.accepting_new_requests).toBe(false);

    // The ordinary drain still reports itself; the split is not a rename.
    const drained = clusterStatus({ activeRevision: "abc", draining: true });
    expect(drained.readiness_reason).toBe("operator_drain");
    expect(drained.draining).toBe(true);
  });
});

describe("Workers-specific inputs", () => {
  it("drainStatus mirrors accepting_new_requests", () => {
    expect(drainStatus({ GATEWAY_DRAIN: "true" })).toStrictEqual({
      draining: true,
      accepting_new_requests: false,
    });
    expect(drainStatus(undefined)).toStrictEqual({
      draining: false,
      accepting_new_requests: true,
    });
  });

  it("the revision reduces non-serializable bindings to a placeholder", () => {
    // A D1/R2/DO handle cannot be JSON-serialized; hashing the env must not
    // throw, and two deployments with the same binding NAMES agree.
    const binding = { prepare: () => undefined };
    expect(activeRevisionFor({ DB: binding, VAR: "a" })).toBe(
      activeRevisionFor({ DB: { prepare: () => undefined }, VAR: "a" }),
    );
    expect(activeRevisionFor({ DB: binding, VAR: "a" })).not.toBe(
      activeRevisionFor({ DB: binding, VAR: "b" }),
    );
    // Key order must not change the revision.
    expect(activeRevisionFor({ A: "1", B: "2" })).toBe(activeRevisionFor({ B: "2", A: "1" }));
  });
});
